#!/usr/bin/env bash
# Focused contract for bounded, externally observable macOS crash evidence.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GUEST="$ROOT/scripts/e2e-macos-release-network.sh"
TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/nvpn-macos-crash-external.XXXXXX")"
DEFINITIONS="$TMP_ROOT/definitions.sh"

cleanup() {
  rm -rf "$TMP_ROOT"
}
trap cleanup EXIT

fail() {
  echo "macOS crash external-state diagnostics harness failed: $*" >&2
  exit 1
}

bash -n "$GUEST"
grep -Fq 'restart_requested_ms="$(monotonic_ms)"' "$GUEST" \
  || fail "crash recovery budget does not begin at the restart request"
grep -Fq '"$restart_requested_ms" "$expected_bind_receipts" "$old_pid"' "$GUEST" \
  || fail "crash recovery wait does not use the restart request clock"
if grep -Eq 'sudo -n /(bin/cat|usr/bin/stat)' "$GUEST"; then
  fail "the guest harness uses unapproved privileged file inspection"
fi
if grep -Fq 'daemon.cleanup.json' "$GUEST"; then
  fail "the unprivileged guest harness reads the daemon's private journal"
fi
while IFS= read -r sudo_line; do
  sudo_line="${sudo_line#*sudo -n }"
  case "$sudo_line" in
    '"$NVPN_BIN" '* \
      | '/usr/sbin/networksetup '* \
      | '/usr/sbin/networksetup \' \
      | '/bin/kill '* \
      | '/bin/launchctl bootout "$SYSTEM_SERVICE_LABEL"' \
      | '/bin/launchctl bootstrap system "$SYSTEM_SERVICE_PLIST"' \
      | '/bin/launchctl kickstart -k "$SYSTEM_SERVICE_LABEL"') ;;
    *) fail "guest harness sudo command is outside its explicit allowlist: $sudo_line" ;;
  esac
done < <(grep -F 'sudo -n ' "$GUEST")

sed '/^validate_inputs$/,$d' "$GUEST" >"$DEFINITIONS"
export NVPN_MACOS_NETWORK_ROOT="$ROOT"
export NVPN_MACOS_NETWORK_STATE_DIR="$TMP_ROOT/state"
mkdir -p "$NVPN_MACOS_NETWORK_STATE_DIR/results"
# shellcheck disable=SC1090
source "$DEFINITIONS"

STATE_DIR="$NVPN_MACOS_NETWORK_STATE_DIR"
RESULT_DIR="$STATE_DIR/results"
CONFIG="$STATE_DIR/config.toml"
ENDPOINT_FAMILY=ipv4
ENDPOINT_HOST=192.0.2.10
PRIMARY_IFACE=en0
WAIT_SECS=2
SECURE_RESOLVER="$STATE_DIR/nvpn-secure-dns"
MAGIC_RESOLVER="$STATE_DIR/nvpn"
printf 'config\n' >"$CONFIG"
printf 'Managed by nvpn secure DNS\nnameserver 127.0.0.1\n' >"$MAGIC_RESOLVER"

WIREGUARD_INTERFACE_STATUS=0
ENDPOINT_ROUTE_ABSENT_STATUS=1
SECURE_DNS_STATUS=0
RESTART_STATE_STATUS=0
wireguard_interface() {
  ((WIREGUARD_INTERFACE_STATUS == 0)) || return 1
  printf 'utun9\n'
}
wireguard_endpoint_route_state_valid() { [[ "${1:-en0}" == en0 ]]; }
wireguard_split_defaults_absent() {
  ((WIREGUARD_INTERFACE_STATUS != 0))
}
wireguard_endpoint_route_absent() {
  return "$ENDPOINT_ROUTE_ABSENT_STATUS"
}
secure_dns_owned() { return "$SECURE_DNS_STATUS"; }
wireguard_routes_live() { return "$RESTART_STATE_STATUS"; }
runtime_wireguard_state_is() {
  [[ "$1 $2" == 'true true' ]] && return "$RESTART_STATE_STATUS"
  return 1
}
runtime_dns_state_matches() { return "$RESTART_STATE_STATUS"; }
runtime_has_no_fips_peers() { return "$RESTART_STATE_STATUS"; }
no_nvpn_processes() { return 0; }
capture_underlay_routes() { printf 'route snapshot\n'; }
secure_dns_store_state() { printf 'dynamic resolver snapshot\n'; }
nvpn() { printf '{"daemon":{"running":true}}\n'; }

# The startup completion receipt must follow WireGuard setup. It is the public
# log point reached only after mandatory cleanup-ownership persistence succeeds.
cat >"$STATE_DIR/daemon.log" <<'LOG'
daemon: FIPS private mesh on utun8
fips: WG upstream up on utun9 via 192.0.2.1 bound to en0 (split-default kill switch installed)
LOG
if crash_startup_log_order_is_valid; then
  fail "reversed startup persistence ordering was accepted"
fi

cat >"$STATE_DIR/daemon.log" <<'LOG'
fips: WG upstream up on utun9 via 192.0.2.1 bound to en0 (split-default kill switch installed)
LOG
sleep() {
  printf '%s\n' 'daemon: FIPS private mesh on utun8' >>"$STATE_DIR/daemon.log"
}
wait_for_crash_live_precondition \
  || fail "transient external startup state did not converge"
grep -Fxq 'polls=2' "$RESULT_DIR/crash-external-precondition.txt" \
  || fail "external startup precondition was not polled"
grep -Fxq 'startup_log_order=true' \
  "$RESULT_DIR/crash-external-precondition-predicates.txt" \
  || fail "ordered startup completion was not retained"
grep -Fq 'WG upstream up on utun9' \
  "$RESULT_DIR/crash-external-precondition-startup-order.txt" \
  || fail "WireGuard startup receipt was not retained"
grep -Fq 'FIPS private mesh on utun8' \
  "$RESULT_DIR/crash-external-precondition-startup-order.txt" \
  || fail "post-persistence FIPS startup receipt was not retained"

# SIGKILL must fail closed: the daemon, WireGuard utun/split defaults, and
# endpoint bypass route are gone. The secure-DNS ownership state deliberately
# remains so the next daemon can repair it before restoring traffic.
WIREGUARD_INTERFACE_STATUS=1
ENDPOINT_ROUTE_ABSENT_STATUS=0
crash_fail_closed_after_sigkill \
  || fail "fail-closed SIGKILL state was rejected"
record_crash_external_audit after-sigkill \
  || fail "fail-closed SIGKILL audit was rejected"
grep -Fxq 'daemon_absent=true' \
  "$RESULT_DIR/crash-external-after-sigkill-predicates.txt" \
  || fail "SIGKILL audit omitted daemon absence"
grep -Fxq 'wireguard_interface_absent=true' \
  "$RESULT_DIR/crash-external-after-sigkill-predicates.txt" \
  || fail "SIGKILL audit omitted WireGuard interface absence"
grep -Fxq 'endpoint_route_absent=true' \
  "$RESULT_DIR/crash-external-after-sigkill-predicates.txt" \
  || fail "SIGKILL audit omitted endpoint-route absence"
grep -Fxq 'secure_dns_owned=true' \
  "$RESULT_DIR/crash-external-after-sigkill-predicates.txt" \
  || fail "SIGKILL audit omitted secure-DNS repair ownership"

WIREGUARD_INTERFACE_STATUS=0
if crash_fail_closed_after_sigkill; then
  fail "SIGKILL state accepted a surviving WireGuard utun"
fi
failed_predicates="$RESULT_DIR/crash-external-after-sigkill-last-poll.txt"
if snapshot_crash_fail_closed_after_sigkill "$failed_predicates"; then
  fail "SIGKILL predicate snapshot accepted a surviving WireGuard utun"
fi
for predicate in \
  daemon_absent=true \
  wireguard_interface_absent=false \
  wireguard_split_defaults_absent=false \
  endpoint_route_absent=true \
  secure_dns_owned=true
do
  grep -Fxq "$predicate" "$failed_predicates" \
    || fail "SIGKILL last-poll evidence omitted $predicate"
done
WIREGUARD_INTERFACE_STATUS=1
ENDPOINT_ROUTE_ABSENT_STATUS=1
crash_fail_closed_after_sigkill \
  || fail "SIGKILL state rejected a journal-owned endpoint bypass route"
retained_route_predicates="$RESULT_DIR/crash-external-retained-route.txt"
snapshot_crash_fail_closed_after_sigkill "$retained_route_predicates" \
  || fail "SIGKILL snapshot rejected a journal-owned endpoint bypass route"
grep -Fxq 'endpoint_route_absent=false' "$retained_route_predicates" \
  || fail "SIGKILL snapshot hid the retained endpoint bypass route"
ENDPOINT_ROUTE_ABSENT_STATUS=0
SECURE_DNS_STATUS=1
if crash_fail_closed_after_sigkill; then
  fail "SIGKILL state accepted lost secure-DNS repair ownership"
fi
SECURE_DNS_STATUS=0

# Restart acceptance is one atomic production-state predicate: a fresh PID and
# bind, tunnel/routes/DNS, isolated zero-peer runtime, and WG payloads.
assert_single_owned_daemon() { return "$RESTART_STATE_STATUS"; }
owned_daemon_pid() { printf '%s\n' "${RESTART_PID:-202}"; }
wireguard_bind_receipt_count() { printf '%s\n' "${RESTART_BINDS:-2}"; }
captured_probe_works() { return "$RESTART_STATE_STATUS"; }
https_works() { return "$RESTART_STATE_STATUS"; }
exit_source_is_expected() { return "$RESTART_STATE_STATUS"; }
mkdir -p "$RESULT_DIR/crash-restart-probes"
WIREGUARD_INTERFACE_STATUS=0
crash_restart_transport_live 2 101 \
  || fail "complete fresh crash recovery was rejected"
RESTART_PID=101
if crash_restart_transport_live 2 101; then
  fail "crash recovery accepted the killed daemon PID"
fi
RESTART_PID=202
RESTART_BINDS=3
if crash_restart_transport_live 2 101; then
  fail "crash recovery accepted more than one fresh WireGuard bind"
fi
RESTART_BINDS=2
RESTART_STATE_STATUS=1
if crash_restart_transport_live 2 101; then
  fail "crash recovery accepted missing tunnel/DNS/WG state"
fi
RESTART_STATE_STATUS=0

# A stable externally visible failure must retain predicate, route, resolver,
# status, and daemon-log evidence without inspecting the private journal.
WAIT_SECS=1
runtime_dns_state_matches() { return 1; }
sleep() { SECONDS=$((SECONDS + 1)); }
if wait_for_crash_live_precondition; then
  fail "stable external DNS mismatch passed"
fi
capture_crash_external_failure
grep -Fxq 'runtime_dns_state_matches=false' \
  "$RESULT_DIR/crash-external-failure-predicates.txt" \
  || fail "failing DNS predicate was not retained"
grep -Fxq 'route snapshot' \
  "$RESULT_DIR/crash-external-failure-routes.txt" \
  || fail "live routes were not retained"
grep -Fq 'dynamic resolver snapshot' \
  "$RESULT_DIR/crash-external-failure-resolver-state.txt" \
  || fail "live resolver state was not retained"
grep -Fq 'nameserver 127.0.0.1' \
  "$RESULT_DIR/crash-external-failure-resolver-state.txt" \
  || fail "resolver file state was not retained"
grep -Fq '"running":true' \
  "$RESULT_DIR/crash-external-failure-status.json" \
  || fail "daemon status was not retained"
cmp -s "$STATE_DIR/daemon.log" \
  "$RESULT_DIR/crash-external-failure-daemon.log" \
  || fail "the daemon log was not retained exactly"
if find "$STATE_DIR" -name '*cleanup*json' -print -quit | grep -q .; then
  fail "focused test created or inspected a private cleanup journal fixture"
fi

echo "MACOS_CRASH_EXTERNAL_DIAGNOSTICS_HARNESS_OK"
