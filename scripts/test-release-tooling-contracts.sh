#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"
# shellcheck source=scripts/lib-release-gate-parallel.sh
source "$ROOT_DIR/scripts/lib-release-gate-parallel.sh"
# shellcheck disable=SC2329 # Invoked through the parallel lane runner.
run_contract_batch() {
  local contract contract_status status=0
  for contract in "$@"; do
    "$contract" || {
      contract_status="$?"
      ((status != 0)) || status="$contract_status"
    }
  done
  return "$status"
}
log_dir="$(mktemp -d "${TMPDIR:-/tmp}/nvpn-release-tooling-contracts.XXXXXX")"
trap 'release_gate_parallel_cancel_all; rm -rf "$log_dir"' EXIT
release_gate_parallel_init "$log_dir"
lanes=()
start_lane() {
  release_gate_parallel_start "$@"
  lanes+=("$RELEASE_GATE_PARALLEL_LAST_INDEX")
}
start_lane "Node release contracts" node --test scripts/*.test.mjs
start_lane "App Store metadata contracts" \
  python3 scripts/test_appstore_draft_metadata.py
start_lane "release and Windows contracts" run_contract_batch \
  scripts/test-{publish-preflight,build-nvpn-linux-musl-docker-config,windows-installer-migration,windows-wireguard-exit-fixture,android-aab-derived-release,macos-vm-identity-guard}-harness.sh
start_lane "mobile contracts" run_contract_batch \
  scripts/test-mobile-{physical-device-selection,ios-vpn-cleanup,android-release-cleanup,wireguard-exit-dns,wireguard-fixture-cleanup,release-provenance,release-artifact-reuse,underlay-change,release-join-gate}-harness.sh \
  scripts/test-android-release-network-evidence-harness.sh \
  scripts/test-{ios-vpn-desired-state,ios-packet-tunnel-replacement}.sh
start_lane "cross-platform artifact contracts" run_contract_batch \
  scripts/test-{desktop-mobile-manual-join-receipt,mobile-ios-release-runner,windows-release-mobile-join}-harness.sh \
  scripts/test-native-paid-exit-ui-parity.py
start_lane "Apple and desktop contracts" run_contract_batch \
  scripts/test-{macos-vm-import-only,desktop-network-handoff,desktop-dns-ui-evidence,desktop-underlay-host-peer-import,macos-release-fips-roaming,macos-crash-ownership-diagnostics,macos-release-exit-dns-ui,ios-frozen-archive,macos-sdk-compat}-harness.sh
foreground_status=0
for contract in \
  scripts/test-{release-gate-parallel,local-fips-workspace,idle-cpu-gate}-harness.sh
do
  "$contract" || {
    contract_status="$?"
    ((foreground_status != 0)) || foreground_status="$contract_status"
  }
done
parallel_status=0
release_gate_parallel_wait_group "${lanes[@]}" || parallel_status="$?"
trap - EXIT
rm -rf "$log_dir"
((foreground_status == 0)) || exit "$foreground_status"
exit "$parallel_status"
