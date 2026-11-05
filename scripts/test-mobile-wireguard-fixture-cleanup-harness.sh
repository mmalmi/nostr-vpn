#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REMOTE_NATIVE="$ROOT/scripts/mobile-wireguard-exit-remote-native.sh"
# shellcheck disable=SC1091
source "$ROOT/scripts/lib-mobile-wireguard-fixture.sh"
TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/nvpn-wg-cleanup-harness.XXXXXX")"
REMOTE_STATE="$(mktemp -d /var/tmp/nvpn-mobile-wg-exit.cleanup-harness.XXXXXX)"
CALLS="$TMP_ROOT/calls"
trap 'rm -rf "$TMP_ROOT" "$REMOTE_STATE" "${LEASE_A:-}" "${LEASE_B:-}" "${LEASE_C:-}" "${LEASE_HUP:-}"' EXIT

SIGNAL_PROBE="$TMP_ROOT/signal-probe"
mkdir -p "$SIGNAL_PROBE"
(
  cleanup_probe() {
    mobile_wg_fixture_begin_cleanup
    touch "$SIGNAL_PROBE/entered"
    sleep 0.2
    touch "$SIGNAL_PROBE/completed"
    exit 143
  }
  trap cleanup_probe TERM
  touch "$SIGNAL_PROBE/ready"
  while true; do sleep 1; done
) &
signal_pid="$!"
for _ in $(seq 1 50); do
  [[ -f "$SIGNAL_PROBE/ready" ]] && break
  sleep 0.02
done
[[ -f "$SIGNAL_PROBE/ready" ]]
kill -TERM "$signal_pid"
for _ in $(seq 1 50); do
  [[ -f "$SIGNAL_PROBE/entered" ]] && break
  sleep 0.02
done
[[ -f "$SIGNAL_PROBE/entered" ]]
kill -HUP "$signal_pid"
signal_status=0
wait "$signal_pid" || signal_status="$?"
[[ "$signal_status" -eq 143 && -f "$SIGNAL_PROBE/completed" ]]

grep -Fq 'private-key /dev/stdin' "$REMOTE_NATIVE" \
  && grep -Fq 'cat "$NVPN_MOBILE_WG_SERVER_PRIVATE_KEY_FILE"' "$REMOTE_NATIVE" \
  || {
    echo "native fixture does not inherit its ephemeral key past wg AppArmor" >&2
    exit 1
  }

listeners=$'UNCONN 0 0 0.0.0.0:51886 0.0.0.0:*\nLISTEN 0 5 0.0.0.0:53000 0.0.0.0:*'
mobile_wg_listener_port_in_use 51886 "$listeners"
mobile_wg_listener_port_in_use 53000 "$listeners"
if mobile_wg_listener_port_in_use 53001 "$listeners"; then
  echo "fixture listener parser reported an unused port as occupied" >&2
  exit 1
fi

MOBILE_WG_FIXTURE_REMOTE_DIR=/tmp/nvpn-mobile-wg-exit.port-53000
stale_owner_state=present
mobile_wg_remote_native() {
  [[ "$1" == clean && "$stale_owner_state" == present ]]
}
mobile_wg_remote_exec() {
  [[ "${1:-}" == --fresh ]] && shift
  case "$*" in
    "sh -c "*) return 0 ;;
    "test ! -e $MOBILE_WG_FIXTURE_REMOTE_DIR")
      [[ "$stale_owner_state" == absent ]]
      ;;
    "test -d $MOBILE_WG_FIXTURE_REMOTE_DIR"|\
    "test ! -L $MOBILE_WG_FIXTURE_REMOTE_DIR"|\
    "test -O $MOBILE_WG_FIXTURE_REMOTE_DIR")
      [[ "$stale_owner_state" != absent ]]
      ;;
    "find $MOBILE_WG_FIXTURE_REMOTE_DIR -mindepth 1 -maxdepth 1 -print -quit")
      [[ "$stale_owner_state" != absent ]] || return 1
      if [[ "$stale_owner_state" != empty ]]; then
        printf '%s\n' "$MOBILE_WG_FIXTURE_REMOTE_DIR/entry"
      fi
      return 0
      ;;
    "test -f $MOBILE_WG_FIXTURE_REMOTE_DIR/.nvpn-fixture-owner"|\
    "test ! -L $MOBILE_WG_FIXTURE_REMOTE_DIR/.nvpn-fixture-owner"|\
    "test -O $MOBILE_WG_FIXTURE_REMOTE_DIR/.nvpn-fixture-owner"|\
    "test ! -e $MOBILE_WG_FIXTURE_REMOTE_DIR/mobile-wireguard-exit-remote-native.sh")
      [[ "$stale_owner_state" == partial ]]
      ;;
    "sudo -n rm -f $MOBILE_WG_FIXTURE_REMOTE_DIR/fixture/server.key $MOBILE_WG_FIXTURE_REMOTE_DIR/fixture/client.key"|\
    "sudo -n find $MOBILE_WG_FIXTURE_REMOTE_DIR -xdev -depth -mindepth 1 -delete")
      [[ "$stale_owner_state" != absent ]]
      ;;
    "sudo -n rmdir $MOBILE_WG_FIXTURE_REMOTE_DIR")
      stale_owner_state=absent
      ;;
    *) return 1 ;;
  esac
}
mobile_wg_fixture_recover_inactive_remote_dir
[[ "$stale_owner_state" == absent ]]
stale_owner_state=empty
mobile_wg_fixture_recover_inactive_remote_dir
[[ "$stale_owner_state" == absent ]]
stale_owner_state=partial
mobile_wg_fixture_recover_inactive_remote_dir
[[ "$stale_owner_state" == absent ]]
stale_owner_state=active
if mobile_wg_fixture_recover_inactive_remote_dir; then
  echo "fixture recovery removed active same-owner state" >&2
  exit 1
fi
[[ "$stale_owner_state" == active ]]

mobile_wg_remote_close_control() {
  printf 'close\n' >>"$CALLS"
}

mobile_wg_fixture_docker() {
  printf 'docker %s\n' "$*" >>"$CALLS"
  case "$1 $2" in
    "container inspect"|"image inspect") return 1 ;;
    *) return 0 ;;
  esac
}

mobile_wg_remote_exec() {
  printf 'remote %s\n' "$*" >>"$CALLS"
  return 0
}

MOBILE_WG_FIXTURE_STARTED=1
MOBILE_WG_FIXTURE_REMOTE_MODE=docker
MOBILE_WG_FIXTURE_REMOTE_IMAGE_BUILT=1
MOBILE_WG_FIXTURE_REMOTE_DIR=/tmp/nvpn-mobile-wg-exit.success
mobile_wg_fixture_cleanup fixture image
[[ "$MOBILE_WG_FIXTURE_STARTED" -eq 0 ]]
[[ "$MOBILE_WG_FIXTURE_REMOTE_IMAGE_BUILT" -eq 0 ]]
[[ -z "$MOBILE_WG_FIXTURE_REMOTE_DIR" ]]
for expected in \
  'docker rm -f fixture' \
  'docker container inspect fixture' \
  'docker image rm image' \
  'docker image inspect image' \
  'remote --fresh test ! -e /tmp/nvpn-mobile-wg-exit.success' \
  close
do
  grep -Fqx "$expected" "$CALLS"
done

: >"$CALLS"
mobile_wg_fixture_docker() {
  printf 'docker %s\n' "$*" >>"$CALLS"
  case "$1 $2" in
    "container inspect") return 0 ;;
    "image inspect") return 255 ;;
    *) return 0 ;;
  esac
}
mobile_wg_remote_exec() {
  printf 'remote %s\n' "$*" >>"$CALLS"
  [[ "$1" != "test" ]]
}
MOBILE_WG_FIXTURE_STARTED=1
MOBILE_WG_FIXTURE_REMOTE_MODE=docker
MOBILE_WG_FIXTURE_REMOTE_IMAGE_BUILT=1
MOBILE_WG_FIXTURE_REMOTE_DIR=/tmp/nvpn-mobile-wg-exit.failure
if mobile_wg_fixture_cleanup fixture image >/dev/null 2>&1; then
  echo "fixture cleanup accepted retained resources" >&2
  exit 1
fi
[[ "$MOBILE_WG_FIXTURE_STARTED" -eq 1 ]]
[[ "$MOBILE_WG_FIXTURE_REMOTE_IMAGE_BUILT" -eq 1 ]]
[[ "$MOBILE_WG_FIXTURE_REMOTE_DIR" == /tmp/nvpn-mobile-wg-exit.failure ]]
grep -Fqx 'docker image rm image' "$CALLS"
grep -Fqx \
  'remote test ! -e /tmp/nvpn-mobile-wg-exit.failure/fixture/server.key' \
  "$CALLS"
grep -Fqx close "$CALLS"

: >"$CALLS"
mobile_wg_remote_native() {
  printf 'native %s\n' "$*" >>"$CALLS"
  if [[ "$1" == "clean" ]]; then
    return 1
  fi
}
MOBILE_WG_FIXTURE_STARTED=1
MOBILE_WG_FIXTURE_REMOTE_MODE=native
MOBILE_WG_FIXTURE_REMOTE_IMAGE_BUILT=0
MOBILE_WG_FIXTURE_REMOTE_INTERFACE=nwg53000
MOBILE_WG_FIXTURE_REMOTE_NFT_TABLE=nvpnwg53000
MOBILE_WG_FIXTURE_REMOTE_DIR=/tmp/nvpn-mobile-wg-exit.native
if mobile_wg_fixture_cleanup fixture image >/dev/null 2>&1; then
  echo "native fixture cleanup accepted a retained firewall rule" >&2
  exit 1
fi
[[ "$MOBILE_WG_FIXTURE_STARTED" -eq 1 ]]
[[ "$MOBILE_WG_FIXTURE_REMOTE_DIR" == /tmp/nvpn-mobile-wg-exit.native ]]
grep -Fqx 'native stop' "$CALLS"
grep -Fqx 'native clean' "$CALLS"
grep -Fqx \
  'remote test ! -e /tmp/nvpn-mobile-wg-exit.native/fixture/server.key' \
  "$CALLS"
grep -Fqx close "$CALLS"

MOCK_BIN="$TMP_ROOT/bin"
mkdir -p "$MOCK_BIN"
cat >"$MOCK_BIN/nft" <<'SH'
#!/usr/bin/env bash
if [[ -n "${NFT_CALLS:-}" ]]; then
  printf '%s\n' "$*" >>"$NFT_CALLS"
fi
if [[ "$*" == "delete rule ip6 filter INPUT handle 42" ]]; then
  if [[ ("${MOCK_NFT_MODE:-retained}" == "owned" \
      || "${MOCK_NFT_MODE:-retained}" == "large-owned") \
    && -f "${NFT_RULE_STATE:-}" ]]
  then
    rm -f "$NFT_RULE_STATE"
    exit 0
  fi
  exit 1
fi
if [[ "$*" == "list chain ip6 filter INPUT" \
  && ("${MOCK_NFT_MODE:-retained}" == "owned" \
    || "${MOCK_NFT_MODE:-retained}" == "large-owned" \
    || "${MOCK_NFT_MODE:-retained}" == "append-fail" \
    || "${MOCK_NFT_MODE:-retained}" == "precheck-dump-fail" \
    || "${MOCK_NFT_MODE:-retained}" == "transactional-fail") ]]
then
  exit 0
fi
if [[ "$*" == "insert rule ip6 filter INPUT "* \
  && ("${MOCK_NFT_MODE:-retained}" == "large-owned" \
    || "${MOCK_NFT_MODE:-retained}" == "owned" \
    || "${MOCK_NFT_MODE:-retained}" == "append-fail" \
    || "${MOCK_NFT_MODE:-retained}" == "transactional-fail") ]]
then
  touch "$NFT_RULE_STATE"
  exit 0
fi
if [[ "$*" == "-a list chain ip6 filter INPUT" ]]; then
  if [[ "${MOCK_NFT_MODE:-retained}" == "handle-reused" ]]; then
    printf '%s\n' \
      'udp dport 22 accept comment "unrelated-host-rule" # handle 42'
  elif [[ "${MOCK_NFT_MODE:-retained}" == "precheck-dump-fail" ]]; then
    exit 1
  elif [[ "${MOCK_NFT_MODE:-retained}" == "transactional-fail" ]]; then
    [[ ! -f "${NFT_RULE_STATE:-}" ]]
    exit
  elif [[ "${MOCK_NFT_MODE:-retained}" == "append-fail" ]]; then
    if [[ -f "${NFT_RULE_STATE:-}" ]]; then
      chmod 400 "$NFT_RECEIPT_FILE"
      printf '%s\n' \
        'udp dport 55999 accept comment "nvpn-mobile-nwg55999-input-v6" # handle 42'
    fi
  elif [[ "${MOCK_NFT_MODE:-retained}" == "large-owned" ]]; then
    python3 - "${NFT_RULE_STATE:-}" <<'PY'
import pathlib
import sys

state = pathlib.Path(sys.argv[1])
if state.is_file():
    print(
        'udp dport 55999 accept '
        'comment "nvpn-mobile-nwg55999-input-v6" # handle 42'
    )
for handle in range(100_000, 150_000):
    print(f'counter packets 0 bytes 0 # handle {handle}')
PY
    exit $?
  elif [[ ("${MOCK_NFT_MODE:-retained}" != "owned" \
      && "${MOCK_NFT_MODE:-retained}" != "large-owned" \
      && "${MOCK_NFT_MODE:-retained}" != "append-fail" \
      && "${MOCK_NFT_MODE:-retained}" != "transactional-fail") \
    || -f "${NFT_RULE_STATE:-}" ]]
  then
    printf '%s\n' \
      'udp dport 55999 accept comment "nvpn-mobile-nwg55999-input-v6" # handle 42'
  fi
  exit 0
fi
if [[ "$*" == "-a list ruleset" ]]; then
  if [[ "${MOCK_NFT_MODE:-retained}" == "handle-reused" ]]; then
    printf '%s\n' \
      'udp dport 22 accept comment "unrelated-host-rule" # handle 42'
  elif [[ "${MOCK_NFT_MODE:-retained}" == "large-owned" \
    && -f "${NFT_RULE_STATE:-}" ]]
  then
    printf '%s\n' \
      'udp dport 55999 accept comment "nvpn-mobile-nwg55999-input-v6" # handle 42'
  elif [[ ("${MOCK_NFT_MODE:-retained}" != "owned" \
      && "${MOCK_NFT_MODE:-retained}" != "large-owned" \
      && "${MOCK_NFT_MODE:-retained}" != "append-fail" \
      && "${MOCK_NFT_MODE:-retained}" != "transactional-fail") \
    || -f "${NFT_RULE_STATE:-}" ]]
  then
    printf '%s\n' \
      'udp dport 55999 accept comment "nvpn-mobile-nwg55999-input-v6" # handle 42'
  fi
  exit 0
fi
if [[ "$*" == "list table inet nvpnwg55999" ]]; then
  exit 1
fi
exit 1
SH
cat >"$MOCK_BIN/ip" <<'SH'
#!/usr/bin/env bash
if [[ -n "${MOCK_IP_STATE_DIR:-}" && "$1 $2" == "link show" ]]; then
  [[ -f "$MOCK_IP_STATE_DIR/$3" ]]
  exit
fi
if [[ -n "${MOCK_IP_STATE_DIR:-}" && "$1 $2" == "link delete" ]]; then
  rm -f "$MOCK_IP_STATE_DIR/$3"
  exit
fi
exit 1
SH
cat >"$MOCK_BIN/flock" <<'PY'
#!/usr/bin/env python3
import fcntl
import sys

operation, raw_fd = sys.argv[1:]
fd = int(raw_fd)
if operation == "-x":
    fcntl.flock(fd, fcntl.LOCK_EX)
elif operation == "-u":
    fcntl.flock(fd, fcntl.LOCK_UN)
else:
    raise SystemExit(2)
PY
chmod +x "$MOCK_BIN/nft" "$MOCK_BIN/ip" "$MOCK_BIN/flock"
REMOTE_RUNNER="$MOCK_BIN/remote-native-action"
cat >"$REMOTE_RUNNER" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
set --
# shellcheck disable=SC1090
source "$REMOTE_NATIVE_FOR_HARNESS"
ip_forward_lock="$IP_FORWARD_LOCK_FOR_HARNESS"
ip_forward_state="$IP_FORWARD_STATE_FOR_HARNESS"
ip_forward_leases="$ip_forward_state/leases"
ip_forward_original="$ip_forward_state/original"
ip_forward_sysctl="$IP_FORWARD_SYSCTL_FOR_HARNESS"
if [[ "${SLOW_IP_FORWARD_WRITE_FOR_HARNESS:-0}" == "1" ]]; then
  write_ip_forwarding() {
    local value="$1" current
    [[ "$value" == "0" || "$value" == "1" ]] || return 1
    sleep 0.05
    printf '%s\n' "$value" >"$ip_forward_sysctl" || return 1
    current="$(read_ip_forwarding)" || return 1
    [[ "$current" == "$value" ]]
  }
fi
case "$REMOTE_NATIVE_ACTION" in
  clean) assert_fixture_clean ;;
  stop) stop_fixture ;;
  firewall-add)
    : >"$system_firewall_rules"
    add_system_firewall_rule \
      ip6 filter INPUT nvpn-mobile-nwg55999-input-v6 \
      udp dport 55999 accept
    ;;
  lease-acquire) acquire_ip_forward_lease ;;
  lease-stop) release_ip_forward_lease_and_delete_interface ;;
  lease-clean) ip_forward_lease_clean ;;
  fixture-hup-wait)
    install_fixture_cleanup_trap
    : >"$system_firewall_rules"
    add_system_firewall_rule \
      ip6 filter INPUT nvpn-mobile-nwg55999-input-v6 \
      udp dport 55999 accept
    acquire_ip_forward_lease
    printf '%s\n' "$$" >"$HUP_READY_FOR_HARNESS"
    while :; do :; done
    ;;
  *) exit 2 ;;
esac
SH
chmod +x "$REMOTE_RUNNER"
IP_FORWARD_LOCK="$TMP_ROOT/ip-forward.lock"
IP_FORWARD_STATE="$TMP_ROOT/ip-forward-state"
IP_FORWARD_SYSCTL="$TMP_ROOT/ip-forward"
printf '0\n' >"$IP_FORWARD_SYSCTL"

# A marker that predates this insertion attempt is not ours. The add must fail
# before writing a pending receipt, and cleanup must leave that rule untouched.
PREEXISTING_RULE_STATE="$TMP_ROOT/preexisting-rule"
touch "$PREEXISTING_RULE_STATE"
: >"$CALLS"
if env \
    PATH="$MOCK_BIN:/usr/bin:/bin" \
    MOCK_NFT_MODE=owned \
    NFT_CALLS="$CALLS" \
    NFT_RULE_STATE="$PREEXISTING_RULE_STATE" \
    REMOTE_NATIVE_FOR_HARNESS="$REMOTE_NATIVE" \
    REMOTE_NATIVE_ACTION=firewall-add \
    IP_FORWARD_LOCK_FOR_HARNESS="$IP_FORWARD_LOCK" \
    IP_FORWARD_STATE_FOR_HARNESS="$IP_FORWARD_STATE" \
    IP_FORWARD_SYSCTL_FOR_HARNESS="$IP_FORWARD_SYSCTL" \
    NVPN_MOBILE_WG_REMOTE_STATE_DIR="$REMOTE_STATE" \
    NVPN_MOBILE_WG_REMOTE_INTERFACE=nwg55999 \
    NVPN_MOBILE_WG_REMOTE_NFT_TABLE=nvpnwg55999 \
    NVPN_MOBILE_WG_REMOTE_ENDPOINT_FAMILY=ipv6 \
    "$REMOTE_RUNNER" >/dev/null 2>&1
then
  echo "firewall insertion accepted a pre-existing marker" >&2
  exit 1
fi
[[ -e "$PREEXISTING_RULE_STATE" \
  && ! -s "$REMOTE_STATE/system-firewall-rules.tsv" ]]
if env \
    PATH="$MOCK_BIN:/usr/bin:/bin" \
    MOCK_NFT_MODE=owned \
    NFT_CALLS="$CALLS" \
    NFT_RULE_STATE="$PREEXISTING_RULE_STATE" \
    REMOTE_NATIVE_FOR_HARNESS="$REMOTE_NATIVE" \
    REMOTE_NATIVE_ACTION=stop \
    IP_FORWARD_LOCK_FOR_HARNESS="$IP_FORWARD_LOCK" \
    IP_FORWARD_STATE_FOR_HARNESS="$IP_FORWARD_STATE" \
    IP_FORWARD_SYSCTL_FOR_HARNESS="$IP_FORWARD_SYSCTL" \
    NVPN_MOBILE_WG_REMOTE_STATE_DIR="$REMOTE_STATE" \
    NVPN_MOBILE_WG_REMOTE_INTERFACE=nwg55999 \
    NVPN_MOBILE_WG_REMOTE_NFT_TABLE=nvpnwg55999 \
    NVPN_MOBILE_WG_REMOTE_ENDPOINT_FAMILY=ipv6 \
    "$REMOTE_RUNNER" >/dev/null 2>&1
then
  echo "cleanup accepted a pre-existing firewall marker" >&2
  exit 1
fi
[[ -e "$PREEXISTING_RULE_STATE" ]]
if grep -Eq '^(insert|delete) rule ' "$CALLS"; then
  echo "firewall insertion mutated a pre-existing marker" >&2
  exit 1
fi
rm -f "$PREEXISTING_RULE_STATE" \
  "$REMOTE_STATE/system-firewall-rules.tsv"

# A failed full-chain precheck is not proof that the marker is absent, even when
# the failed dump returned no rows. Do not claim ownership or mutate host state.
DUMP_FAILURE_RULE_STATE="$TMP_ROOT/dump-failure-preexisting-rule"
touch "$DUMP_FAILURE_RULE_STATE"
: >"$CALLS"
if env \
    PATH="$MOCK_BIN:/usr/bin:/bin" \
    MOCK_NFT_MODE=precheck-dump-fail \
    NFT_CALLS="$CALLS" \
    NFT_RULE_STATE="$DUMP_FAILURE_RULE_STATE" \
    REMOTE_NATIVE_FOR_HARNESS="$REMOTE_NATIVE" \
    REMOTE_NATIVE_ACTION=firewall-add \
    IP_FORWARD_LOCK_FOR_HARNESS="$IP_FORWARD_LOCK" \
    IP_FORWARD_STATE_FOR_HARNESS="$IP_FORWARD_STATE" \
    IP_FORWARD_SYSCTL_FOR_HARNESS="$IP_FORWARD_SYSCTL" \
    NVPN_MOBILE_WG_REMOTE_STATE_DIR="$REMOTE_STATE" \
    NVPN_MOBILE_WG_REMOTE_INTERFACE=nwg55999 \
    NVPN_MOBILE_WG_REMOTE_NFT_TABLE=nvpnwg55999 \
    NVPN_MOBILE_WG_REMOTE_ENDPOINT_FAMILY=ipv6 \
    "$REMOTE_RUNNER" >/dev/null 2>&1
then
  echo "firewall insertion accepted a failed marker precheck" >&2
  exit 1
fi
[[ -e "$DUMP_FAILURE_RULE_STATE" \
  && ! -s "$REMOTE_STATE/system-firewall-rules.tsv" ]]
if grep -Eq '^(insert|delete) rule ' "$CALLS"; then
  echo "failed marker precheck mutated host firewall state" >&2
  exit 1
fi
rm -f "$DUMP_FAILURE_RULE_STATE" \
  "$REMOTE_STATE/system-firewall-rules.tsv"

# The real host chain is large enough that an awk early-exit makes nft receive
# SIGPIPE under pipefail. This producer puts the marker first and keeps writing;
# insertion must still record both its pending recovery marker and exact handle.
LARGE_RULE_STATE="$TMP_ROOT/large-owned-rule"
touch "$LARGE_RULE_STATE"
set +e
MOCK_NFT_MODE=large-owned \
  NFT_RULE_STATE="$LARGE_RULE_STATE" \
  "$MOCK_BIN/nft" -a list chain ip6 filter INPUT 2>/dev/null \
  | awk '/nvpn-mobile-nwg55999-input-v6/ { exit }' >/dev/null
old_early_exit_status=$?
set -e
[[ "$old_early_exit_status" -ne 0 ]] || {
  echo "large nft producer cannot reproduce the old SIGPIPE failure" >&2
  exit 1
}
rm -f "$LARGE_RULE_STATE"
: >"$CALLS"
env \
  PATH="$MOCK_BIN:/usr/bin:/bin" \
  MOCK_NFT_MODE=large-owned \
  NFT_CALLS="$CALLS" \
  NFT_RULE_STATE="$LARGE_RULE_STATE" \
  REMOTE_NATIVE_FOR_HARNESS="$REMOTE_NATIVE" \
  REMOTE_NATIVE_ACTION=firewall-add \
  IP_FORWARD_LOCK_FOR_HARNESS="$IP_FORWARD_LOCK" \
  IP_FORWARD_STATE_FOR_HARNESS="$IP_FORWARD_STATE" \
  IP_FORWARD_SYSCTL_FOR_HARNESS="$IP_FORWARD_SYSCTL" \
  NVPN_MOBILE_WG_REMOTE_STATE_DIR="$REMOTE_STATE" \
  NVPN_MOBILE_WG_REMOTE_INTERFACE=nwg55999 \
  NVPN_MOBILE_WG_REMOTE_NFT_TABLE=nvpnwg55999 \
  NVPN_MOBILE_WG_REMOTE_ENDPOINT_FAMILY=ipv6 \
  "$REMOTE_RUNNER"
grep -Fqx \
  $'ip6\tfilter\tINPUT\tpending\tnvpn-mobile-nwg55999-input-v6' \
  "$REMOTE_STATE/system-firewall-rules.tsv"
grep -Fqx \
  $'ip6\tfilter\tINPUT\t42\tnvpn-mobile-nwg55999-input-v6' \
  "$REMOTE_STATE/system-firewall-rules.tsv"
env \
  PATH="$MOCK_BIN:/usr/bin:/bin" \
  MOCK_NFT_MODE=large-owned \
  NFT_CALLS="$CALLS" \
  NFT_RULE_STATE="$LARGE_RULE_STATE" \
  REMOTE_NATIVE_FOR_HARNESS="$REMOTE_NATIVE" \
  REMOTE_NATIVE_ACTION=stop \
  IP_FORWARD_LOCK_FOR_HARNESS="$IP_FORWARD_LOCK" \
  IP_FORWARD_STATE_FOR_HARNESS="$IP_FORWARD_STATE" \
  IP_FORWARD_SYSCTL_FOR_HARNESS="$IP_FORWARD_SYSCTL" \
  NVPN_MOBILE_WG_REMOTE_STATE_DIR="$REMOTE_STATE" \
  NVPN_MOBILE_WG_REMOTE_INTERFACE=nwg55999 \
  NVPN_MOBILE_WG_REMOTE_NFT_TABLE=nvpnwg55999 \
  NVPN_MOBILE_WG_REMOTE_ENDPOINT_FAMILY=ipv6 \
  "$REMOTE_RUNNER"
[[ ! -e "$LARGE_RULE_STATE" \
  && ! -e "$REMOTE_STATE/system-firewall-rules.tsv" ]] || {
  echo "large host-chain cleanup did not consume its recoverable receipt" >&2
  exit 1
}

# If insertion succeeds but the immediate handle lookup fails, the pending
# receipt must be sufficient for the next cleanup attempt to remove it.
TRANSACTION_RULE_STATE="$TMP_ROOT/transaction-rule"
: >"$CALLS"
if env \
    PATH="$MOCK_BIN:/usr/bin:/bin" \
    MOCK_NFT_MODE=transactional-fail \
    NFT_CALLS="$CALLS" \
    NFT_RULE_STATE="$TRANSACTION_RULE_STATE" \
    REMOTE_NATIVE_FOR_HARNESS="$REMOTE_NATIVE" \
    REMOTE_NATIVE_ACTION=firewall-add \
    IP_FORWARD_LOCK_FOR_HARNESS="$IP_FORWARD_LOCK" \
    IP_FORWARD_STATE_FOR_HARNESS="$IP_FORWARD_STATE" \
    IP_FORWARD_SYSCTL_FOR_HARNESS="$IP_FORWARD_SYSCTL" \
    NVPN_MOBILE_WG_REMOTE_STATE_DIR="$REMOTE_STATE" \
    NVPN_MOBILE_WG_REMOTE_INTERFACE=nwg55999 \
    NVPN_MOBILE_WG_REMOTE_NFT_TABLE=nvpnwg55999 \
    NVPN_MOBILE_WG_REMOTE_ENDPOINT_FAMILY=ipv6 \
    "$REMOTE_RUNNER" >/dev/null 2>&1
then
  echo "firewall insertion accepted a failed handle lookup" >&2
  exit 1
fi
[[ -e "$TRANSACTION_RULE_STATE" ]]
[[ "$(<"$REMOTE_STATE/system-firewall-rules.tsv")" \
  == $'ip6\tfilter\tINPUT\tpending\tnvpn-mobile-nwg55999-input-v6' ]]
env \
  PATH="$MOCK_BIN:/usr/bin:/bin" \
  MOCK_NFT_MODE=owned \
  NFT_CALLS="$CALLS" \
  NFT_RULE_STATE="$TRANSACTION_RULE_STATE" \
  REMOTE_NATIVE_FOR_HARNESS="$REMOTE_NATIVE" \
  REMOTE_NATIVE_ACTION=stop \
  IP_FORWARD_LOCK_FOR_HARNESS="$IP_FORWARD_LOCK" \
  IP_FORWARD_STATE_FOR_HARNESS="$IP_FORWARD_STATE" \
  IP_FORWARD_SYSCTL_FOR_HARNESS="$IP_FORWARD_SYSCTL" \
  NVPN_MOBILE_WG_REMOTE_STATE_DIR="$REMOTE_STATE" \
  NVPN_MOBILE_WG_REMOTE_INTERFACE=nwg55999 \
  NVPN_MOBILE_WG_REMOTE_NFT_TABLE=nvpnwg55999 \
  NVPN_MOBILE_WG_REMOTE_ENDPOINT_FAMILY=ipv6 \
  "$REMOTE_RUNNER"
[[ ! -e "$TRANSACTION_RULE_STATE" \
  && ! -e "$REMOTE_STATE/system-firewall-rules.tsv" ]] || {
  echo "pending firewall receipt did not recover an inserted rule" >&2
  exit 1
}

# A successful insert and handle lookup can still lose the exact receipt append
# (for example, storage becoming unwritable). The already-durable pending row
# must recover that rule too.
APPEND_RULE_STATE="$TMP_ROOT/append-rule"
: >"$CALLS"
if env \
    PATH="$MOCK_BIN:/usr/bin:/bin" \
    MOCK_NFT_MODE=append-fail \
    NFT_CALLS="$CALLS" \
    NFT_RULE_STATE="$APPEND_RULE_STATE" \
    NFT_RECEIPT_FILE="$REMOTE_STATE/system-firewall-rules.tsv" \
    REMOTE_NATIVE_FOR_HARNESS="$REMOTE_NATIVE" \
    REMOTE_NATIVE_ACTION=firewall-add \
    IP_FORWARD_LOCK_FOR_HARNESS="$IP_FORWARD_LOCK" \
    IP_FORWARD_STATE_FOR_HARNESS="$IP_FORWARD_STATE" \
    IP_FORWARD_SYSCTL_FOR_HARNESS="$IP_FORWARD_SYSCTL" \
    NVPN_MOBILE_WG_REMOTE_STATE_DIR="$REMOTE_STATE" \
    NVPN_MOBILE_WG_REMOTE_INTERFACE=nwg55999 \
    NVPN_MOBILE_WG_REMOTE_NFT_TABLE=nvpnwg55999 \
    NVPN_MOBILE_WG_REMOTE_ENDPOINT_FAMILY=ipv6 \
    "$REMOTE_RUNNER" >/dev/null 2>&1
then
  echo "firewall insertion accepted a failed exact receipt append" >&2
  exit 1
fi
chmod 600 "$REMOTE_STATE/system-firewall-rules.tsv"
[[ -e "$APPEND_RULE_STATE" ]]
[[ "$(<"$REMOTE_STATE/system-firewall-rules.tsv")" \
  == $'ip6\tfilter\tINPUT\tpending\tnvpn-mobile-nwg55999-input-v6' ]]
env \
  PATH="$MOCK_BIN:/usr/bin:/bin" \
  MOCK_NFT_MODE=owned \
  NFT_CALLS="$CALLS" \
  NFT_RULE_STATE="$APPEND_RULE_STATE" \
  REMOTE_NATIVE_FOR_HARNESS="$REMOTE_NATIVE" \
  REMOTE_NATIVE_ACTION=stop \
  IP_FORWARD_LOCK_FOR_HARNESS="$IP_FORWARD_LOCK" \
  IP_FORWARD_STATE_FOR_HARNESS="$IP_FORWARD_STATE" \
  IP_FORWARD_SYSCTL_FOR_HARNESS="$IP_FORWARD_SYSCTL" \
  NVPN_MOBILE_WG_REMOTE_STATE_DIR="$REMOTE_STATE" \
  NVPN_MOBILE_WG_REMOTE_INTERFACE=nwg55999 \
  NVPN_MOBILE_WG_REMOTE_NFT_TABLE=nvpnwg55999 \
  NVPN_MOBILE_WG_REMOTE_ENDPOINT_FAMILY=ipv6 \
  "$REMOTE_RUNNER"
[[ ! -e "$APPEND_RULE_STATE" \
  && ! -e "$REMOTE_STATE/system-firewall-rules.tsv" ]] || {
  echo "pending receipt did not recover a failed exact receipt append" >&2
  exit 1
}

printf 'ip6\tfilter\tINPUT\t42\tnvpn-mobile-nwg55999-input-v6\n' \
  >"$REMOTE_STATE/system-firewall-rules.tsv"
if env \
    PATH="$MOCK_BIN:/usr/bin:/bin" \
    REMOTE_NATIVE_FOR_HARNESS="$REMOTE_NATIVE" \
    REMOTE_NATIVE_ACTION=clean \
    IP_FORWARD_LOCK_FOR_HARNESS="$IP_FORWARD_LOCK" \
    IP_FORWARD_STATE_FOR_HARNESS="$IP_FORWARD_STATE" \
    IP_FORWARD_SYSCTL_FOR_HARNESS="$IP_FORWARD_SYSCTL" \
    NVPN_MOBILE_WG_REMOTE_STATE_DIR="$REMOTE_STATE" \
    NVPN_MOBILE_WG_REMOTE_INTERFACE=nwg55999 \
    NVPN_MOBILE_WG_REMOTE_NFT_TABLE=nvpnwg55999 \
    NVPN_MOBILE_WG_REMOTE_ENDPOINT_FAMILY=ipv6 \
    NVPN_MOBILE_WG_LISTEN_PORT=55999 \
    "$REMOTE_RUNNER" >/dev/null 2>&1
then
  echo "remote native clean accepted a retained host firewall rule" >&2
  exit 1
fi
[[ -f "$REMOTE_STATE/system-firewall-rules.tsv" ]] || {
  echo "remote native clean discarded the retained firewall receipt" >&2
  exit 1
}

rm -f "$REMOTE_STATE/system-firewall-rules.tsv"
if env \
    PATH="$MOCK_BIN:/usr/bin:/bin" \
    REMOTE_NATIVE_FOR_HARNESS="$REMOTE_NATIVE" \
    REMOTE_NATIVE_ACTION=clean \
    IP_FORWARD_LOCK_FOR_HARNESS="$IP_FORWARD_LOCK" \
    IP_FORWARD_STATE_FOR_HARNESS="$IP_FORWARD_STATE" \
    IP_FORWARD_SYSCTL_FOR_HARNESS="$IP_FORWARD_SYSCTL" \
    NVPN_MOBILE_WG_REMOTE_STATE_DIR="$REMOTE_STATE" \
    NVPN_MOBILE_WG_REMOTE_INTERFACE=nwg55999 \
    NVPN_MOBILE_WG_REMOTE_NFT_TABLE=nvpnwg55999 \
    NVPN_MOBILE_WG_REMOTE_ENDPOINT_FAMILY=ipv6 \
    NVPN_MOBILE_WG_LISTEN_PORT=55999 \
    "$REMOTE_RUNNER" >/dev/null 2>&1
then
  echo "remote native clean accepted an unrecorded host firewall rule" >&2
  exit 1
fi

: >"$CALLS"
printf '%s\n%s\n' \
  $'ip6\tfilter\tINPUT\tpending\tnvpn-mobile-nwg55999-input-v6' \
  $'ip6\tfilter\tINPUT\t42\tnvpn-mobile-nwg55999-input-v6' \
  >"$REMOTE_STATE/system-firewall-rules.tsv"
if ! env \
    PATH="$MOCK_BIN:/usr/bin:/bin" \
    MOCK_NFT_MODE=handle-reused \
    NFT_CALLS="$CALLS" \
    REMOTE_NATIVE_FOR_HARNESS="$REMOTE_NATIVE" \
    REMOTE_NATIVE_ACTION=stop \
    IP_FORWARD_LOCK_FOR_HARNESS="$IP_FORWARD_LOCK" \
    IP_FORWARD_STATE_FOR_HARNESS="$IP_FORWARD_STATE" \
    IP_FORWARD_SYSCTL_FOR_HARNESS="$IP_FORWARD_SYSCTL" \
    NVPN_MOBILE_WG_REMOTE_STATE_DIR="$REMOTE_STATE" \
    NVPN_MOBILE_WG_REMOTE_INTERFACE=nwg55999 \
    NVPN_MOBILE_WG_REMOTE_NFT_TABLE=nvpnwg55999 \
    NVPN_MOBILE_WG_REMOTE_ENDPOINT_FAMILY=ipv6 \
    NVPN_MOBILE_WG_LISTEN_PORT=55999 \
    "$REMOTE_RUNNER"
then
  echo "remote native cleanup rejected safe firewall handle reuse" >&2
  exit 1
fi
if grep -Fq 'delete rule ip6 filter INPUT handle 42' "$CALLS"; then
  echo "remote native cleanup deleted a reused unrelated firewall handle" >&2
  exit 1
fi
[[ ! -f "$REMOTE_STATE/system-firewall-rules.tsv" ]] || {
  echo "remote native cleanup retained a stale receipt after safe handle reuse" >&2
  exit 1
}

: >"$CALLS"
RULE_STATE="$TMP_ROOT/owned-rule"
touch "$RULE_STATE"
printf 'ip6\tfilter\tINPUT\t42\tnvpn-mobile-nwg55999-input-v6\n' \
  >"$REMOTE_STATE/system-firewall-rules.tsv"
env \
  PATH="$MOCK_BIN:/usr/bin:/bin" \
  MOCK_NFT_MODE=owned \
  NFT_CALLS="$CALLS" \
  NFT_RULE_STATE="$RULE_STATE" \
  REMOTE_NATIVE_FOR_HARNESS="$REMOTE_NATIVE" \
  REMOTE_NATIVE_ACTION=stop \
  IP_FORWARD_LOCK_FOR_HARNESS="$IP_FORWARD_LOCK" \
  IP_FORWARD_STATE_FOR_HARNESS="$IP_FORWARD_STATE" \
  IP_FORWARD_SYSCTL_FOR_HARNESS="$IP_FORWARD_SYSCTL" \
  NVPN_MOBILE_WG_REMOTE_STATE_DIR="$REMOTE_STATE" \
  NVPN_MOBILE_WG_REMOTE_INTERFACE=nwg55999 \
  NVPN_MOBILE_WG_REMOTE_NFT_TABLE=nvpnwg55999 \
  NVPN_MOBILE_WG_REMOTE_ENDPOINT_FAMILY=ipv6 \
  NVPN_MOBILE_WG_LISTEN_PORT=55999 \
  "$REMOTE_RUNNER"
grep -Fqx 'delete rule ip6 filter INPUT handle 42' "$CALLS"
[[ ! -e "$RULE_STATE" \
  && ! -e "$REMOTE_STATE/system-firewall-rules.tsv" ]] || {
  echo "remote native cleanup did not remove its owned firewall rule" >&2
  exit 1
}

printf '999999\n' >"$REMOTE_STATE/dnsmasq.pid"
env \
  PATH="$MOCK_BIN:/usr/bin:/bin" \
  MOCK_NFT_MODE=handle-reused \
  REMOTE_NATIVE_FOR_HARNESS="$REMOTE_NATIVE" \
  REMOTE_NATIVE_ACTION=clean \
  IP_FORWARD_LOCK_FOR_HARNESS="$IP_FORWARD_LOCK" \
  IP_FORWARD_STATE_FOR_HARNESS="$IP_FORWARD_STATE" \
  IP_FORWARD_SYSCTL_FOR_HARNESS="$IP_FORWARD_SYSCTL" \
  NVPN_MOBILE_WG_REMOTE_STATE_DIR="$REMOTE_STATE" \
  NVPN_MOBILE_WG_REMOTE_INTERFACE=nwg55999 \
  NVPN_MOBILE_WG_REMOTE_NFT_TABLE=nvpnwg55999 \
  NVPN_MOBILE_WG_REMOTE_ENDPOINT_FAMILY=ipv6 \
  NVPN_MOBILE_WG_LISTEN_PORT=55999 \
  "$REMOTE_RUNNER"

LEASE_A="$(mktemp -d /tmp/nvpn-mobile-wg-exit.lease-a.XXXXXX)"
LEASE_B="$(mktemp -d /var/tmp/nvpn-mobile-wg-exit.lease-b.XXXXXX)"
LEASE_C="$(mktemp -d /tmp/nvpn-mobile-wg-exit.lease-c.XXXXXX)"
LEASE_HUP="$(mktemp -d /tmp/nvpn-mobile-wg-exit.lease-hup.XXXXXX)"
MOCK_IP_STATE="$TMP_ROOT/interfaces"
mkdir -p "$MOCK_IP_STATE"

run_lease_action() {
  local lease_action="$1" lease_state="$2" lease_interface="$3"
  local slow_write="${4:-0}"
  env \
    PATH="$MOCK_BIN:/usr/bin:/bin" \
    MOCK_IP_STATE_DIR="$MOCK_IP_STATE" \
    MOCK_NFT_MODE="${MOCK_NFT_MODE:-handle-reused}" \
    NFT_RULE_STATE="${NFT_RULE_STATE:-}" \
    NFT_CALLS="${NFT_CALLS:-}" \
    REMOTE_NATIVE_FOR_HARNESS="$REMOTE_NATIVE" \
    REMOTE_NATIVE_ACTION="$lease_action" \
    SLOW_IP_FORWARD_WRITE_FOR_HARNESS="$slow_write" \
    HUP_READY_FOR_HARNESS="${HUP_READY_FOR_HARNESS:-}" \
    IP_FORWARD_LOCK_FOR_HARNESS="$IP_FORWARD_LOCK" \
    IP_FORWARD_STATE_FOR_HARNESS="$IP_FORWARD_STATE" \
    IP_FORWARD_SYSCTL_FOR_HARNESS="$IP_FORWARD_SYSCTL" \
    NVPN_MOBILE_WG_REMOTE_STATE_DIR="$lease_state" \
    NVPN_MOBILE_WG_REMOTE_INTERFACE="$lease_interface" \
    NVPN_MOBILE_WG_REMOTE_NFT_TABLE="nvpn$lease_interface" \
    NVPN_MOBILE_WG_REMOTE_ENDPOINT_FAMILY=ipv6 \
    bash "$REMOTE_RUNNER"
}

assert_forwarding_lease_invariant() {
  local before after leases=""
  before="$(<"$IP_FORWARD_SYSCTL")"
  if [[ -d "$IP_FORWARD_STATE/leases" ]]; then
    leases="$(
      find "$IP_FORWARD_STATE/leases" -maxdepth 1 -type f -size +0c \
        -print 2>/dev/null || true
    )"
  fi
  after="$(<"$IP_FORWARD_SYSCTL")"
  if [[ "$before" == "0" && "$after" == "0" && -n "$leases" ]]; then
    echo "IPv4 forwarding was restored while a fixture lease remained" >&2
    return 1
  fi
}

wait_for_lease_jobs() {
  local first_pid="$1" second_pid="$2" failed=0
  while kill -0 "$first_pid" 2>/dev/null \
    || kill -0 "$second_pid" 2>/dev/null
  do
    assert_forwarding_lease_invariant || failed=1
    sleep 0.01
  done
  wait "$first_pid" || failed=1
  wait "$second_pid" || failed=1
  assert_forwarding_lease_invariant || failed=1
  return "$failed"
}

assert_zero_leases_and_original() {
  local expected="$1"
  [[ "$(<"$IP_FORWARD_SYSCTL")" == "$expected" \
    && ! -e "$IP_FORWARD_STATE" ]] || {
    echo "IPv4 forwarding lease state did not restore its original value" >&2
    return 1
  }
}

# Both mobile lanes acquire distinct leases concurrently. Stopping either
# owner must leave forwarding enabled until the last owner releases.
printf '0\n' >"$IP_FORWARD_SYSCTL"
touch "$MOCK_IP_STATE/nwg56001" "$MOCK_IP_STATE/nwg56002"
run_lease_action lease-acquire "$LEASE_A" nwg56001 1 &
lease_a_pid=$!
run_lease_action lease-acquire "$LEASE_B" nwg56002 1 &
lease_b_pid=$!
wait_for_lease_jobs "$lease_a_pid" "$lease_b_pid"
[[ "$(<"$IP_FORWARD_SYSCTL")" == "1" \
  && "$(<"$IP_FORWARD_STATE/leases/nwg56001")" == "$LEASE_A" \
  && "$(<"$IP_FORWARD_STATE/leases/nwg56002")" == "$LEASE_B" ]]
run_lease_action lease-stop "$LEASE_A" nwg56001
[[ "$(<"$IP_FORWARD_SYSCTL")" == "1" \
  && ! -e "$IP_FORWARD_STATE/leases/nwg56001" \
  && -f "$IP_FORWARD_STATE/leases/nwg56002" ]]
run_lease_action lease-stop "$LEASE_B" nwg56002
assert_zero_leases_and_original 0

# Reverse stop order and preserve an originally-enabled host value.
printf '1\n' >"$IP_FORWARD_SYSCTL"
touch "$MOCK_IP_STATE/nwg56001" "$MOCK_IP_STATE/nwg56002"
run_lease_action lease-acquire "$LEASE_A" nwg56001 1 &
lease_a_pid=$!
run_lease_action lease-acquire "$LEASE_B" nwg56002 1 &
lease_b_pid=$!
wait_for_lease_jobs "$lease_a_pid" "$lease_b_pid"
run_lease_action lease-stop "$LEASE_B" nwg56002
[[ "$(<"$IP_FORWARD_SYSCTL")" == "1" \
  && -f "$IP_FORWARD_STATE/leases/nwg56001" \
  && ! -e "$IP_FORWARD_STATE/leases/nwg56002" ]]
run_lease_action lease-stop "$LEASE_A" nwg56001
assert_zero_leases_and_original 1

# Interleave the last owner's stop with a new fixture start. The flock covers
# lease release through interface deletion, so either ordering leaves the new
# owner valid and forwarding enabled without a lease-plus-zero observation.
printf '0\n' >"$IP_FORWARD_SYSCTL"
touch "$MOCK_IP_STATE/nwg56001" "$MOCK_IP_STATE/nwg56003"
run_lease_action lease-acquire "$LEASE_A" nwg56001
run_lease_action lease-stop "$LEASE_A" nwg56001 1 &
lease_a_pid=$!
run_lease_action lease-acquire "$LEASE_C" nwg56003 1 &
lease_c_pid=$!
wait_for_lease_jobs "$lease_a_pid" "$lease_c_pid"
[[ "$(<"$IP_FORWARD_SYSCTL")" == "1" \
  && ! -e "$IP_FORWARD_STATE/leases/nwg56001" \
  && "$(<"$IP_FORWARD_STATE/leases/nwg56003")" == "$LEASE_C" \
  && ! -e "$MOCK_IP_STATE/nwg56001" \
  && -e "$MOCK_IP_STATE/nwg56003" ]]
run_lease_action lease-stop "$LEASE_C" nwg56003
assert_zero_leases_and_original 0

# A lease whose validated owner/interface relationship no longer exists is
# retained for diagnosis; a new lane must not silently prune or replace it.
mkdir -p "$IP_FORWARD_STATE/leases"
printf '0\n' >"$IP_FORWARD_STATE/original"
printf '1\n' >"$IP_FORWARD_SYSCTL"
printf '%s\n' "$LEASE_A" >"$IP_FORWARD_STATE/leases/nwg56001"
rm -f "$MOCK_IP_STATE/nwg56001"
touch "$MOCK_IP_STATE/nwg56002"
if run_lease_action lease-acquire "$LEASE_B" nwg56002 >/dev/null 2>&1; then
  echo "IPv4 forwarding lease accepted stale shared state" >&2
  exit 1
fi
[[ "$(<"$IP_FORWARD_STATE/leases/nwg56001")" == "$LEASE_A" \
  && ! -e "$IP_FORWARD_STATE/leases/nwg56002" \
  && "$(<"$IP_FORWARD_SYSCTL")" == "1" ]]
rm -rf "$IP_FORWARD_STATE"

# SSH commonly terminates the remote process with SIGHUP. Exercise the exact
# production trap after a real add receipt and prove rule, receipt, lease, and
# interface cleanup all complete.
printf '0\n' >"$IP_FORWARD_SYSCTL"
touch "$MOCK_IP_STATE/nwg55999"
HUP_READY="$TMP_ROOT/hup-ready"
HUP_RULE_STATE="$TMP_ROOT/hup-rule"
HUP_READY_FOR_HARNESS="$HUP_READY" \
MOCK_NFT_MODE=owned \
NFT_RULE_STATE="$HUP_RULE_STATE" \
  run_lease_action fixture-hup-wait "$LEASE_HUP" nwg55999 &
hup_pid=$!
for _ in $(seq 1 200); do
  [[ -f "$HUP_READY" ]] && break
  kill -0 "$hup_pid" 2>/dev/null || break
  sleep 0.01
done
[[ -f "$HUP_READY" ]] || {
  echo "SIGHUP cleanup fixture did not acquire its rule and lease" >&2
  kill "$hup_pid" 2>/dev/null || true
  wait "$hup_pid" 2>/dev/null || true
  exit 1
}
[[ -e "$HUP_RULE_STATE" ]]
grep -Fqx \
  $'ip6\tfilter\tINPUT\tpending\tnvpn-mobile-nwg55999-input-v6' \
  "$LEASE_HUP/system-firewall-rules.tsv"
grep -Fqx \
  $'ip6\tfilter\tINPUT\t42\tnvpn-mobile-nwg55999-input-v6' \
  "$LEASE_HUP/system-firewall-rules.tsv"
hup_target="$(<"$HUP_READY")"
[[ "$hup_target" =~ ^[1-9][0-9]*$ ]]
kill -HUP "$hup_target"
set +e
wait "$hup_pid"
hup_status=$?
set -e
[[ "$hup_status" -ne 0 \
  && ! -e "$MOCK_IP_STATE/nwg55999" \
  && ! -e "$HUP_RULE_STATE" \
  && ! -e "$LEASE_HUP/system-firewall-rules.tsv" ]]
assert_zero_leases_and_original 0

echo "mobile WireGuard fixture cleanup harness passed"
