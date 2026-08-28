#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
# Keep the escalation path covered without making this focused harness pay the
# production two-second grace period.
# shellcheck disable=SC2034 # Read by the sourced runner.
export RELEASE_GATE_PARALLEL_TERM_GRACE_SECONDS=1
# shellcheck disable=SC1091
source "$ROOT_DIR/scripts/lib-release-gate-parallel.sh"

fail() {
  printf 'release gate parallel harness failed: %s\n' "$*" >&2
  exit 1
}

tmp="$(mktemp -d "${TMPDIR:-/tmp}/nvpn-release-gate-parallel.XXXXXX")"
trap 'release_gate_parallel_cancel_all; rm -rf "$tmp"' EXIT
release_gate_parallel_init "$tmp/logs"

# A lane may never consume input intended for the release controller.
if ! stdin_probe_output="$(
  printf 'controller-sentinel\n' \
    | /bin/bash -c '
        set -euo pipefail
        root_dir="$1"
        log_dir="$2"
        source "$root_dir/scripts/lib-release-gate-parallel.sh"
        trap "release_gate_parallel_cancel_all" EXIT
        release_gate_parallel_init "$log_dir"
        lane_reads_stdin() {
          local value
          if IFS= read -r value; then
            printf "lane read controller input: %s\n" "$value"
            return 1
          fi
          printf "lane stdin reached EOF\n"
        }
        release_gate_parallel_start "stdin isolation" lane_reads_stdin >/dev/null
        release_gate_parallel_wait "$RELEASE_GATE_PARALLEL_LAST_INDEX"
      ' _ "$ROOT_DIR" "$tmp/stdin-logs" 2>&1
)"; then
  fail "parallel lane inherited controller stdin: $stdin_probe_output"
fi
[[ "$stdin_probe_output" == *"lane stdin reached EOF"* ]] \
  || fail "parallel stdin probe did not observe EOF"

# The process-group scan must consume all ps output under pipefail.
if ! (
  # shellcheck disable=SC2329 # Invoked through the sourced runner.
  ps() {
    printf '424242 S\n'
    awk 'BEGIN { for (row = 0; row < 10000; row += 1) print "1 S" }'
  }
  release_gate_parallel_group_alive 424242
); then
  fail "process-group probe stopped reading ps output under pipefail"
fi

lane_waits_for_peer() {
  local peer_marker="$1" own_marker="$2"
  local end=$(( $(date +%s) + 5 ))
  : >"$own_marker"
  while [[ ! -f "$peer_marker" && "$(date +%s)" -le "$end" ]]; do
    sleep 0.02
  done
  [[ -f "$peer_marker" ]]
  printf 'saw peer lane\n'
}

release_gate_parallel_start \
  "first lane" lane_waits_for_peer "$tmp/second" "$tmp/first"
first="$RELEASE_GATE_PARALLEL_LAST_INDEX"
release_gate_parallel_start \
  "second lane" lane_waits_for_peer "$tmp/first" "$tmp/second"
second="$RELEASE_GATE_PARALLEL_LAST_INDEX"
release_gate_parallel_wait_group "$first" "$second" >/dev/null
grep -Fq 'saw peer lane' "$tmp/logs/first-lane-0.log" \
  || fail "first lane did not run concurrently"
grep -Fq 'saw peer lane' "$tmp/logs/second-lane-1.log" \
  || fail "second lane did not run concurrently"

lane_fails() {
  printf 'intentional lane failure\n'
  return 7
}

lane_fails_before_followup() {
  lane_fails
  : >"$tmp/continued-after-failure"
}

release_gate_parallel_start "failing lane" lane_fails
failing="$RELEASE_GATE_PARALLEL_LAST_INDEX"
set +e
release_gate_parallel_wait "$failing" >/dev/null 2>&1
status=$?
set -e
[[ "$status" == 7 ]] \
  || fail "failing lane returned $status instead of 7"
grep -Fq 'intentional lane failure' "$tmp/logs/failing-lane-2.log" \
  || fail "failing lane log was not preserved"

# A failed lane must not cancel or hide an independent peer's result.
collect_peer() {
  sleep 0.2
  printf 'independent lane completed\n'
  : >"$tmp/collect-complete"
}

release_gate_parallel_start "independent peer" collect_peer
peer="$RELEASE_GATE_PARALLEL_LAST_INDEX"
release_gate_parallel_start "collected failure" lane_fails_before_followup
collected_failure="$RELEASE_GATE_PARALLEL_LAST_INDEX"
set +e
release_gate_parallel_wait_group "$peer" "$collected_failure" >/dev/null 2>&1
status=$?
set -e
[[ "$status" == 7 ]] \
  || fail "parallel group returned $status instead of the collected failure"
[[ -f "$tmp/collect-complete" ]] \
  || fail "a failed lane cancelled its independent peer"
[[ ! -e "$tmp/continued-after-failure" ]] \
  || fail "a failed lane continued mutating after its first error"
grep -Fq 'independent lane completed' "${RELEASE_GATE_PARALLEL_LOGS[$peer]}" \
  || fail "independent peer log was not preserved"
[[ -z "${RELEASE_GATE_PARALLEL_PIDS[$peer]:-}" ]] \
  || fail "parallel group did not reap its completed peer"

# A successful wrapper with a stubborn child must fail closed and leave no
# process behind. This exercises TERM and KILL escalation, not source strings.
orphan_lane() {
  (
    trap 'printf "term received\n" >"$1"' TERM
    : >"$2"
    while :; do
      sleep 10 || true
    done
  ) &
  printf '%s\n' "$!" >"$3"
  while [[ ! -f "$2" ]]; do
    sleep 0.02
  done
}

release_gate_parallel_start \
  "successful lane with orphan" orphan_lane \
  "$tmp/orphan-term" "$tmp/orphan-ready" "$tmp/orphan.pid"
orphan="$RELEASE_GATE_PARALLEL_LAST_INDEX"
orphan_pgid="${RELEASE_GATE_PARALLEL_PGIDS[$orphan]}"
for _ in $(seq 1 50); do
  [[ -s "$tmp/orphan.pid" && -f "$tmp/orphan-ready" ]] && break
  sleep 0.02
done
[[ -s "$tmp/orphan.pid" && -f "$tmp/orphan-ready" ]] \
  || fail "orphan fixture did not start"
orphan_child="$(<"$tmp/orphan.pid")"
release_gate_parallel_pid_live_in_group "$orphan_child" "$orphan_pgid" \
  || fail "orphan fixture escaped its lane process group"
set +e
release_gate_parallel_wait "$orphan" >/dev/null 2>&1
status=$?
set -e
[[ "$status" == 1 ]] \
  || fail "successful lane with an orphan returned $status instead of failing closed"
[[ -f "$tmp/orphan-term" ]] \
  || fail "orphan did not receive TERM before escalation"
if release_gate_parallel_group_alive "$orphan_pgid"; then
  fail "orphan process group survived cleanup"
fi
[[ -z "${RELEASE_GATE_PARALLEL_PIDS[$orphan]:-}" \
  && -z "${RELEASE_GATE_PARALLEL_PGIDS[$orphan]:-}" ]] \
  || fail "orphan lane was not reaped"

release_gate_parallel_wait_group \
  || fail "empty parallel group did not complete successfully"

# Retain the Bash-3/nounset regression without duplicating the lane tests.
if ! fully_drained_output="$(
  /bin/bash -c '
    set -euo pipefail
    source "$1/scripts/lib-release-gate-parallel.sh"
    release_gate_parallel_init "$2"
    release_gate_parallel_start first true >/dev/null
    first="$RELEASE_GATE_PARALLEL_LAST_INDEX"
    release_gate_parallel_start second true >/dev/null
    second="$RELEASE_GATE_PARALLEL_LAST_INDEX"
    release_gate_parallel_wait_group "$first" "$second" >/dev/null
    printf "fully drained join passed\n"
  ' _ "$ROOT_DIR" "$tmp/fully-drained-logs" 2>&1
)"; then
  fail "fully drained parallel group failed: $fully_drained_output"
fi
[[ "$fully_drained_output" == *"fully drained join passed"* ]] \
  || fail "fully drained parallel group did not finish its join"

release_gate="$ROOT_DIR/scripts/release-gate.sh"
local_release="$ROOT_DIR/scripts/local-release.mjs"
release_tooling_contracts="$ROOT_DIR/scripts/test-release-tooling-contracts.sh"

# Complete mode normalizes auto-detected network lanes to the literal
# "required" value. Every dispatcher receiving that normalized value must
# treat it like its explicit enabled mode rather than rejecting it after the
# expensive platform lanes have already completed.
windows_wg_dispatcher="$(sed -n \
  '/^run_windows_wireguard_exit_gate()/,/^}/p' "$release_gate")"
grep -Fq \
  '1|true|TRUE|True|yes|YES|Yes|on|ON|On|windows-vm|required)' \
  <<<"$windows_wg_dispatcher" \
  || fail "Windows WireGuard dispatcher rejects complete-mode required"
for dispatcher in \
  run_mobile_wireguard_exit_gates \
  run_mobile_underlay_change_gates
do
  dispatcher_body="$(sed -n "/^${dispatcher}()/,/^}/p" "$release_gate")"
  grep -Fq \
    '1|true|TRUE|True|yes|YES|Yes|on|ON|On|required)' \
    <<<"$dispatcher_body" \
    || fail "$dispatcher rejects complete-mode required"
done
[[ -x "$release_tooling_contracts" ]] \
  || fail "release tooling contracts have no standalone executable"
grep -Fq 'name: Release tooling contracts' "$ROOT_DIR/.github/workflows/ci.yml" \
  || fail "release tooling contracts do not run as an independent CI job"
! grep -Fq 'test-release-tooling-contracts.sh' "$release_gate" \
  || fail "artifact certification still reruns release-tooling contracts"
grep -Fq 'node --test scripts/*.test.mjs' "$release_tooling_contracts" \
  || fail "release tooling contracts do not run every Node contract test"
required_modes_lib="$ROOT_DIR/scripts/lib-release-gate-required-modes.sh"
# shellcheck disable=SC1090
source "$required_modes_lib"

# Complete releases force every real network lane while developer runs retain
# auto-detection. Test the policy as code, including its fail-closed branch.
complete_network_modes=(
  NVPN_RELEASE_GATE_WINDOWS_WG_EXIT_E2E
  NVPN_RELEASE_GATE_WINDOWS_UNDERLAY_NETWORK_CHANGE_E2E
  NVPN_RELEASE_GATE_MACOS_WG_EXIT_E2E
  NVPN_RELEASE_GATE_LINUX_UNDERLAY_NETWORK_CHANGE_E2E
  NVPN_RELEASE_GATE_MOBILE_WG_EXIT_E2E
  NVPN_RELEASE_GATE_MOBILE_UNDERLAY_E2E
)
for name in "${complete_network_modes[@]}"; do
  unset "$name"
done
export NVPN_RELEASE_GATE_REQUIRE_COMPLETE=0
release_gate_enforce_complete_real_network_modes
for name in "${complete_network_modes[@]}"; do
  [[ -z "${!name:-}" ]] \
    || fail "developer release gate unexpectedly forced $name"
done
export NVPN_RELEASE_GATE_REQUIRE_COMPLETE=1
for name in "${complete_network_modes[@]}"; do
  printf -v "$name" '%s' auto
  export "${name?}"
done
release_gate_enforce_complete_real_network_modes
for name in "${complete_network_modes[@]}"; do
  [[ "${!name:-}" == required ]] \
    || fail "complete release gate did not force $name"
done
export NVPN_RELEASE_GATE_MOBILE_UNDERLAY_E2E=0
if release_gate_enforce_complete_real_network_modes >/dev/null 2>&1; then
  fail "complete release gate accepted a disabled real network mode"
fi
export NVPN_RELEASE_GATE_MOBILE_UNDERLAY_E2E=required

unset NVPN_MOBILE_WG_EXIT_FIXTURE_SSH_HOST
unset NVPN_MOBILE_WG_EXIT_HOST_IP
unset NVPN_WINDOWS_WG_FIXTURE_HOST_IP
unset NVPN_MACOS_WG_FIXTURE_HOST_IP
unset NVPN_WINDOWS_WG_EXIT_CONFIG_FILE
unset NVPN_WG_EXIT_CONFIG_FILE
if release_gate_require_complete_fixture_inputs >/dev/null 2>&1; then
  fail "complete release gate accepted missing WireGuard fixture inputs"
fi
export NVPN_WINDOWS_WG_FIXTURE_HOST_IP=192.0.2.10
export NVPN_MOBILE_WG_EXIT_HOST_IP=192.0.2.10
if release_gate_require_complete_fixture_inputs >/dev/null 2>&1; then
  fail "complete release gate accepted a missing macOS local fixture address"
fi
export NVPN_MACOS_WG_FIXTURE_HOST_IP=192.0.2.10
export NVPN_DESKTOP_UNDERLAY_HYPERVISOR_SSH=hypervisor.test
export NVPN_WINDOWS_UNDERLAY_VM_NAME=windows-test
if release_gate_require_complete_fixture_inputs >/dev/null 2>&1; then
  fail "complete release gate accepted a missing Linux underlay VM name"
fi
export NVPN_LINUX_UNDERLAY_VM_NAME=linux-test
export NVPN_MOBILE_WG_EXIT_FIXTURE_SSH_HOST=wireguard-fixture.test
export NVPN_MOBILE_WG_EXIT_REMOTE_MODE=native
release_gate_require_complete_fixture_inputs \
  || fail "complete release gate rejected remote-native WireGuard fixture inputs"

# Exercise candidate receipts rather than asserting their implementation text.
receipt_functions="$tmp/platform-preparation-receipts.sh"
sed -n '/^write_platform_preparation_receipt() {$/,/^}$/p' \
  "$release_gate" >"$receipt_functions"
sed -n '/^platform_preparation_receipt_valid() {$/,/^}$/p' \
  "$release_gate" >>"$receipt_functions"
receipt_repo="$tmp/receipt-repo"
mkdir -p "$receipt_repo"
git -C "$receipt_repo" init -q
git -C "$receipt_repo" config user.email release-gate@example.invalid
git -C "$receipt_repo" config user.name 'Release gate fixture'
printf 'candidate\n' >"$receipt_repo/product"
git -C "$receipt_repo" add product
git -C "$receipt_repo" commit -qm candidate
(
  release_root="$ROOT_DIR"
  ROOT_DIR="$receipt_repo"
  # shellcheck disable=SC1090
  # shellcheck disable=SC1091
  source "$release_root/scripts/release_common.sh"
  # shellcheck disable=SC1090
  source "$receipt_functions"
  receipt="$tmp/platform.receipt"
  write_platform_preparation_receipt "$receipt" windows
  platform_preparation_receipt_valid "$receipt" windows \
    || fail "exact platform receipt was rejected"
  if platform_preparation_receipt_valid "$receipt" macos; then
    fail "platform receipt was reusable by another platform"
  fi
  printf 'dirty\n' >>"$receipt_repo/product"
  if write_platform_preparation_receipt "$tmp/dirty.receipt" windows \
    >/dev/null 2>&1
  then
    fail "platform receipt accepted a dirty checkout"
  fi
  git -C "$receipt_repo" add product
  git -C "$receipt_repo" commit -qm changed-candidate
  if platform_preparation_receipt_valid "$receipt" windows; then
    fail "platform receipt survived a candidate change"
  fi
)

# The orchestrator owns only this high-level contract. Platform harnesses own
# their selectors, retry timing, fixture implementation, and cache details.
main_body="$(sed -n '/^main() {$/,$p' "$release_gate")"
static_preflight_body="$(
  sed -n '/^run_release_gate_static_preflight() {$/,/^}$/p' "$release_gate"
)"
ios_framework_build_line="$(
  grep -nF 'NVPN_IOS_RUST_PROFILE=release ./tools/run-ios xcframework' \
    <<<"$static_preflight_body" \
    | cut -d: -f1 \
    || true
)"
ios_policy_check_line="$(
  grep -nF './scripts/test-ios-appstore-policy.sh' \
    <<<"$static_preflight_body" \
    | cut -d: -f1 \
    || true
)"
[[ -n "$ios_framework_build_line" ]] \
  || fail "clean release preflight does not build the packaged iOS XCFramework"
[[ -n "$ios_policy_check_line" ]] \
  || fail "clean release preflight omits the packaged iOS policy check"
((ios_framework_build_line < ios_policy_check_line)) \
  || fail "packaged iOS policy is checked before its release XCFramework is built"
required_steps=(
  seal_release_gate_app_candidate
  run_release_gate_candidate_preflight
  release_gate_enforce_complete_real_network_modes
  prepare_windows_platform_lane_sync
  prepare_macos_platform_lane_sync
  prepare_linux_platform_lane_sync
  platform_preparation_receipt_valid
  run_windows_platform_lane
  run_macos_platform_lane
  run_linux_platform_lane
  run_android_static_validation_lane
  build_release_gate_docker_images
  run_host_validation_lane
  run_desktop_app_launch_smokes
  run_linux_exclusive_desktop_gates
  run_windows_exclusive_desktop_gates
  run_macos_exclusive_desktop_gates
  run_mobile_qr_join_latency_gate
  run_public_fips_transit_gate
  run_docker_signal_gates
  run_docker_isolated_functional_gates
  run_docker_perf_gate
  run_macos_daemon_idle_cpu_gate
  run_mobile_idle_cpu_gates
  run_mobile_wireguard_exit_gates
  verify_paid_exit_seller_ui_gates
  run_android_legacy_replacement_gate
  run_mobile_underlay_change_gates
  run_mobile_join_e2e_gate
  run_windows_release_mobile_join_e2e_gate
  run_linux_release_mobile_join_e2e_gate
  seal_frozen_ios_release_gate
)
for step in "${required_steps[@]}"; do
  grep -Fq "$step" <<<"$main_body" \
    || fail "release gate omits required step: $step"
done

docker_image_build_body="$(
  sed -n '/^build_release_gate_docker_images() {$/,/^}$/p' "$release_gate"
)"
previous_build_line=0
for image_build in \
  build_release_gate_docker_node_image \
  build_release_gate_paid_exit_image \
  build_release_gate_web_image
do
  [[ "$(grep -Fc "$image_build" <<<"$docker_image_build_body")" == "1" ]] \
    || fail "reusable Docker image lane must run $image_build exactly once"
  build_line="$(grep -nF "$image_build" <<<"$docker_image_build_body" | cut -d: -f1)"
  ((build_line > previous_build_line)) \
    || fail "reusable Docker image builds are not serialized in the required order"
  previous_build_line="$build_line"
done
for old_parallel_build in \
  'Docker node image build' \
  'Docker paid-exit image build' \
  'Docker web image build'
do
  ! grep -Fq "$old_parallel_build" <<<"$main_body" \
    || fail "release gate still starts an unsafe parallel image build: $old_parallel_build"
done

required_contracts=(
  'export NVPN_EXPECTED_APP_GIT_SHA="$app_sha"'
  'export NVPN_EXPECTED_APP_GIT_TREE="$app_tree"'
  'candidate_root="$(cd "$ROOT_DIR" && pwd -P)"'
  'export NVPN_RELEASE_APP_REPO_PATH="$candidate_root"'
  'release_gate_parallel_cancel_all || cleanup_failed=1'
  'release_gate_cleanup_private_build_dirs || cleanup_failed=1'
  'platform_preparation_receipt_valid'
  'NVPN_RELEASE_JOIN_ANDROID_INSTALL_RECEIPT='
  'NVPN_RELEASE_JOIN_ANDROID_FIPS_METADATA_RECEIPT='
  'NVPN_RELEASE_JOIN_REUSE_ARTIFACTS=1'
  'export NVPN_EXIT_NODE_E2E_SKIP_BUILD=1'
  'export NVPN_WEB_STARTOS_JOIN_IMAGE_READY=1'
  'export NVPN_UMBREL_WEB_E2E_SKIP_BUILD=1'
  'NVPN_HOST_LINUX_VM_BUILDER_MODE=remote-native'
  'NVPN_HOST_LINUX_VM_NATIVE_BUILDER_HOST="${NVPN_HOST_LINUX_VM_NATIVE_BUILDER_HOST:-$NVPN_UBUNTU_SSH_HOST}"'
  'NVPN_HOST_LINUX_VM_NATIVE_BUILDER_PROXY_COMMAND="${NVPN_HOST_LINUX_VM_NATIVE_BUILDER_PROXY_COMMAND:-${NVPN_UBUNTU_SSH_PROXY_COMMAND:-}}"'
)
for contract in "${required_contracts[@]}"; do
  grep -Fq "$contract" "$release_gate" \
    || fail "release gate omits artifact/cleanup contract: $contract"
done

seal_candidate_line="$(
  grep -nF 'seal_release_gate_app_candidate' <<<"$main_body" \
    | head -n1 \
    | cut -d: -f1 \
    || true
)"
candidate_preflight_line="$(
  grep -nF 'run_release_gate_candidate_preflight' <<<"$main_body" \
    | head -n1 \
    | cut -d: -f1 \
    || true
)"
[[ -n "$seal_candidate_line" && -n "$candidate_preflight_line" ]] \
  || fail "release gate does not seal the app candidate before preflight"
((seal_candidate_line < candidate_preflight_line)) \
  || fail "release gate snapshots the candidate before sealing its app revision"
docker_functional_body="$(sed -n '/^run_docker_isolated_functional_gates() {$/,/^}$/p' "$release_gate")"
for contract in \
  './scripts/e2e-paid-exit-docker.sh' \
  './scripts/e2e-paid-exit-automatic-docker.sh' \
  'NVPN_RELEASE_GATE_PAID_EXIT_IMAGE' \
  'NVPN_RELEASE_GATE_PAID_EXIT_AUTO_IMAGE' \
  'NVPN_RELEASE_GATE_PAID_EXIT_PROJECT_NAME' \
  'NVPN_RELEASE_GATE_PAID_EXIT_AUTO_PROJECT_NAME' \
  'NVPN_RELEASE_GATE_PAID_EXIT_PUBLIC_SUBNET' \
  'NVPN_RELEASE_GATE_PAID_EXIT_PRIVATE_SUBNET' \
  'NVPN_RELEASE_GATE_PAID_EXIT_AUTO_PUBLIC_SUBNET' \
  'NVPN_RELEASE_GATE_PAID_EXIT_AUTO_PRIVATE_SUBNET'; do
  grep -Fq "$contract" <<<"$docker_functional_body" \
    || fail "isolated Docker gates omit paid-exit contract: $contract"
done
grep -Fq 'NVPN_RELEASE_GATE_PAID_EXIT_AUTO_IMAGE:-${NVPN_RELEASE_GATE_PAID_EXIT_IMAGE' \
  <<<"$docker_functional_body" \
  || fail "manual and automatic paid-exit lanes do not reuse one exact image"
umbrel_web_e2e="$ROOT_DIR/scripts/e2e-umbrel-web-docker.sh"
grep -Fq 'NVPN_UMBREL_WEB_E2E_SKIP_BUILD' "$umbrel_web_e2e" \
  || fail "Umbrel web e2e cannot reuse the release gate's exact prebuilt image"
exit_node_e2e="$ROOT_DIR/scripts/e2e-exit-node-docker.sh"
for contract in \
  'HOST_LOG_DIR="$(mktemp -d ' \
  'PUBLIC_PING_LOG="$HOST_LOG_DIR/public-ping.log"' \
  'REALIZED_IP_LOG="$HOST_LOG_DIR/realized-ip.log"' \
  'SECURE_DNS_LOG="$HOST_LOG_DIR/secure-dns.log"' \
  'rm -rf "$HOST_LOG_DIR"'; do
  grep -Fq "$contract" "$exit_node_e2e" \
    || fail "parallel paid-exit lanes do not isolate host logs: $contract"
done
if grep -Eq '/tmp/nvpn-exit-node-(public-ping|realized-ip|secure-dns)\.log' \
  "$exit_node_e2e"; then
  fail "parallel paid-exit lanes still share fixed host log paths"
fi
seller_ui_body="$(sed -n '/^verify_paid_exit_seller_ui_gates() {$/,/^}$/p' "$release_gate")"
for platform in linux macos; do
  grep -Fq "\"$platform=" <<<"$seller_ui_body" \
    || fail "seller UI receipt gate omits supported platform: $platform"
done
for platform in android windows; do
  if grep -Fq "\"$platform=" <<<"$seller_ui_body"; then
    fail "seller UI receipt gate requires unsupported platform: $platform"
  fi
done
grep -Fq 'EXPECTED_PLATFORMS = {"linux", "macos"}' \
  "$ROOT_DIR/scripts/verify-paid-exit-seller-ui-receipts.py" \
  || fail "seller UI receipt verifier differs from the product support matrix"
grep -Fq 'run_umbrel_release_gate' <<<"$docker_functional_body" \
  || fail "isolated Docker gates omit the authenticated Umbrel release gate"
umbrel_function="$(sed -n '/^run_umbrel_release_gate() {$/,/^}$/p' "$release_gate")"
grep -Fq 'pnpm --dir "$ROOT_DIR/web/control-panel" install --frozen-lockfile' \
  <<<"$umbrel_function" \
  || fail "Umbrel release gate assumes preinstalled Playwright dependencies"
umbrel_gate="$ROOT_DIR/scripts/e2e-umbrel-auth-join-docker.sh"
[[ -x "$umbrel_gate" ]] \
  || fail "authenticated Umbrel release gate is missing or not executable"
for contract in \
  'getumbrel/app-proxy:1.7.0@sha256:' \
  'getumbrel/auth-server:1.7.0@sha256:' \
  'nvpn://join-request/' \
  'scanner_web:' \
  "getByPlaceholder('Paste a join request to continue').fill(request)" \
  'requester was not added to the scanner roster' \
  'requester did not activate the scanned network' \
  'A joined device deliberately retains a reusable request link' \
  "getByRole('dialog', { name: 'Add Network' }).waitFor({ state: 'hidden', timeout: 15_000 })" \
  '/dev/net/tun:/dev/net/tun' \
  'PROXY_PORT: $PROXY_PORT' \
  '127.0.0.1:$PROXY_PORT:$PROXY_PORT' \
  'UMBREL_PROXY_TOKEN'; do
  grep -Fq "$contract" "$umbrel_gate" \
    || fail "authenticated Umbrel gate omits contract: $contract"
done
grep -Fq "NVPN_RELEASE_GATE_REQUIRE_COMPLETE: '1'" "$local_release" \
  || fail "full release does not require complete real-network coverage"

# Focused Rust gates must fail when a stale selector runs zero tests.
selector_function="$tmp/release-gate-test-selector.sh"
sed -n '/^release_gate_cargo_test_filter() (/ , /^)/p' \
  "$release_gate" >"$selector_function"
# shellcheck disable=SC1090
source "$selector_function"
zero_match_output="$tmp/zero-match.log"
if release_gate_cargo_test_filter nvpn-fips-core stale_selector \
  printf '%s\n' 'running 0 tests' \
  'test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured' \
  >"$zero_match_output" 2>&1
then
  fail "focused release-gate tests can pass with an empty selector"
fi
grep -Fq 'Release gate test selector matched no passing test: stale_selector (nvpn-fips-core)' \
  "$zero_match_output" \
  || fail "zero-match selector did not explain its failure"
release_gate_cargo_test_filter nvpn-fips-core current_regression \
  printf '%s\n' 'running 1 test' \
  'test module::current_regression ... ok' \
  'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured' \
  >/dev/null \
  || fail "focused selector rejected a matching passing test"

printf 'release gate parallel harness passed\n'
