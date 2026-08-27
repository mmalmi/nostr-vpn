#!/usr/bin/env bash
# Source contract for the imported macos-utm WireGuard release lane. The
# historical filename is retained because release-component provenance names it.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTROLLER="$ROOT/scripts/macos-vm-desktop-wireguard-exit-e2e.sh"
GUEST="$ROOT/scripts/e2e-macos-release-network.sh"
TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/nvpn-macos-wg-local.XXXXXX")"
trap 'rm -rf "$TMP_ROOT"' EXIT

fail() {
  echo "macOS local WireGuard release contract failed: $*" >&2
  exit 1
}

require_tokens() {
  local path="$1" label="$2"
  shift 2
  local token
  for token in "$@"; do
    grep -Fq -- "$token" "$path" \
      || fail "$label is missing: $token"
  done
}

bash -n "$CONTROLLER"
bash -n "$GUEST"

require_tokens "$CONTROLLER" "host-local exit fixture" \
  'FIXTURE_HOST="${NVPN_MACOS_WG_FIXTURE_HOST_IP:-}"' \
  'unset NVPN_MOBILE_WG_EXIT_FIXTURE_SSH_HOST' \
  'mobile_wg_fixture_initialize "$ROOT" "$FIXTURE_DIR"' \
  'mobile_wg_fixture_build "$ROOT" "$IMAGE" 0' \
  'mobile_wg_fixture_run "$IMAGE" "$CONTAINER"' \
  'TARGET_CONTAINER="${NVPN_MACOS_WG_TARGET_CONTAINER:-$CONTAINER-target}"' \
  '--entrypoint python3' \
  'FORWARDED_PROBE_IP="$(' \
  'NVPN_MACOS_CAPTURED_PROBE_URL=http://$FORWARDED_PROBE_IP' \
  'mobile_wg_fixture_wg_bytes' \
  'mobile_wg_fixture_forward_packets' \
  'mobile_wg_fixture_dns_evidence_snapshot' \
  'mobile_wg_fixture_assert_dns_case_evidence' \
  'wait_for_fixture_dns_quiet' \
  'RUST_LOG=info,nvpn::secure_dns_runtime=debug' \
  'MACOS_VM_WIREGUARD_EXIT_E2E_OK'

for forbidden in \
  NVPN_MOBILE_WG_EXIT_FIXTURE_SSH_HOST= \
  mobile_wg_remote_exec \
  FIPS_PEER_SSH_HOST \
  FIPS_PEER_CONTAINER \
  fips_peer_remote \
  prepare_fips_peer_binary
do
  grep -Fq "$forbidden" "$CONTROLLER" \
    && fail "controller retains remote/peer fixture coupling: $forbidden"
done

for forbidden in \
  NVPN_MACOS_EXPECTED_EXIT_SOURCE_IP \
  NVPN_MACOS_SOURCE_IP_URL \
  NVPN_MACOS_INTERNET_URL
do
  grep -Fq "$forbidden" "$CONTROLLER" \
    && fail "controller retains a public Internet probe: $forbidden"
  grep -Fq "$forbidden" "$GUEST" \
    && fail "guest retains a public Internet probe: $forbidden"
done

for dns_case in \
  automatic-profile cloudflare-doh quad9-doh custom-doh through-exit
do
  grep -Fq "$dns_case" "$CONTROLLER" \
    || fail "controller omits resolver case $dns_case"
done

require_tokens "$GUEST" "production WireGuard lifecycle" \
  'NVPN_MACOS_VM_IMPORT_ONLY' \
  'codesign --verify --strict' \
  '--wireguard-exit-config-file "$WG_CONFIG"' \
  '--wireguard-exit-enabled true' \
  '--autoconnect false' \
  'runtime_has_no_fips_peers' \
  'state.get("mesh_ready") is False' \
  'state.get("vpn_status") == "Waiting for participants"' \
  'state.get("connected_peer_count") == 0' \
  'wireguard_endpoint_route_state_valid' \
  'wireguard_routes_live' \
  'runtime_dns_state_matches' \
  'capture_dns_case_failure' \
  'dns-$DNS_LABEL-daemon.log' \
  'dns-$DNS_LABEL-status.json' \
  'payload_after "$requested_ms"' \
  'wireguard_last_rebind_target_is "$expected_iface"' \
  'wait_for_crash_live_precondition' \
  'crash_fail_closed_after_sigkill' \
  'crash_restart_payloads_live' \
  'sudo -n /bin/kill -KILL "$old_pid"' \
  'runtime_wireguard_state_is false true' \
  'runtime_wireguard_state_is false false' \
  'MACOS_RELEASE_NETWORK_UNDERLAY_OK' \
  'MACOS_RELEASE_NETWORK_CRASH_RESTART_OK' \
  'MACOS_RELEASE_NETWORK_DIRECT_OK'

for forbidden in \
  FIPS_PEER_NPUB \
  FIPS_PEER_ENDPOINT \
  FIPS_PEER_TUNNEL_IP \
  runtime_fips_peer_connected \
  fips_payload_loop \
  fips-payload.pid
do
  grep -Fq "$forbidden" "$GUEST" \
    && fail "WireGuard guest lane retains peer coupling: $forbidden"
done

for forbidden in \
  'cargo build' \
  'xcodebuild' \
  'macos-build' \
  'codesign --force' \
  '/usr/bin/swift' \
  'swiftc'
do
  grep -Fq "$forbidden" "$GUEST" \
    && fail "guest network path can build or sign: $forbidden"
done

POLL_DEFINITION="$TMP_ROOT/poll-remote-underlay-status.sh"
sed -n '/^poll_remote_underlay_status() {/,/^}/p' \
  "$CONTROLLER" >"$POLL_DEFINITION"
[[ -s "$POLL_DEFINITION" ]] || fail "underlay status poll helper is missing"
if grep -Eq '(^|[^A-Za-z0-9_])status=' "$POLL_DEFINITION"; then
  fail "underlay poll assigns zsh's read-only status parameter"
fi
POLL_STATE_DIR="$TMP_ROOT/poll-state"
mkdir -p "$POLL_STATE_DIR"
bash -s -- "$POLL_DEFINITION" "$POLL_STATE_DIR" <<'BASH'
set -euo pipefail
source "$1"
REMOTE_DIR="$2"
remote_shell() {
  [[ "$1" == secondary ]]
  zsh -f -c "$2"
}
printf 'pass\n' >"$REMOTE_DIR/underlay.status"
[[ "$(poll_remote_underlay_status)" == pass ]]
printf 'fail:37\n' >"$REMOTE_DIR/underlay.status"
[[ "$(poll_remote_underlay_status)" == fail:37 ]]
BASH

echo "MACOS_RELEASE_LOCAL_WIREGUARD_HARNESS_OK"
