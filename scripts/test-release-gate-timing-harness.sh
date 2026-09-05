#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/lib-release-gate-timing.sh
source "$ROOT_DIR/scripts/lib-release-gate-timing.sh"
# shellcheck source=scripts/lib-release-gate-parallel.sh
source "$ROOT_DIR/scripts/lib-release-gate-parallel.sh"

fail() {
  printf 'release gate timing harness failed: %s\n' "$*" >&2
  exit 1
}

tmp="$(mktemp -d "${TMPDIR:-/tmp}/nvpn-release-gate-timing.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT

release_gate_timing_init "$tmp/logs"
[[ -f "$RELEASE_GATE_TIMING_FILE" ]] \
  || fail "timing ledger was not created"

release_gate_timing_run success true \
  || fail "successful phase was rejected"
if /bin/bash -c '
  set -euo pipefail
  source "$1"
  release_gate_timing_init "$2"
  trap '\''release_gate_timing_finish_active "$?"'\'' EXIT
  release_gate_timing_run failure bash -c "exit 7"
' _ "$ROOT_DIR/scripts/lib-release-gate-timing.sh" "$tmp/failure-logs"
then
  fail "failed phase was masked"
else
  status="$?"
fi
[[ "$status" -eq 7 ]] || fail "failed phase exit status changed"

masked_failure_marker="$tmp/continued-after-failure"
if /bin/bash -c '
  set -euo pipefail
  source "$1"
  release_gate_timing_init "$2"
  marker="$3"
  fails_before_success() {
    false
    : >"$marker"
  }
  trap '\''release_gate_timing_finish_active "$?"'\'' EXIT
  release_gate_timing_run fail-fast-function fails_before_success
' _ "$ROOT_DIR/scripts/lib-release-gate-timing.sh" \
  "$tmp/fail-fast-logs" "$masked_failure_marker"
then
  fail "failed command inside a timed function was masked"
else
  status="$?"
fi
[[ "$status" -ne 0 ]] || fail "timed function failure exit status changed"
[[ ! -e "$masked_failure_marker" ]] \
  || fail "timed function continued after its first failure"

grep -Eq '^serial\tsuccess\t[0-9]+\t[0-9]+\t[0-9]+\t0$' \
  "$RELEASE_GATE_TIMING_FILE" \
  || fail "successful serial phase was not recorded"
grep -Eq '^serial\tfailure\t[0-9]+\t[0-9]+\t[0-9]+\t7$' \
  "$tmp/failure-logs/release-gate-timings.tsv" \
  || fail "failed serial phase was not recorded"
grep -Eq '^serial\tfail-fast-function\t[0-9]+\t[0-9]+\t[0-9]+\t1$' \
  "$tmp/fail-fast-logs/release-gate-timings.tsv" \
  || fail "fail-fast function phase was not recorded"

release_gate_parallel_init "$tmp/logs"
release_gate_parallel_start "parallel success" true
parallel_index="$RELEASE_GATE_PARALLEL_LAST_INDEX"
release_gate_parallel_wait "$parallel_index" >/dev/null \
  || fail "successful parallel phase was rejected"
grep -Eq '^parallel\tparallel success\t[0-9]+\t[0-9]+\t[0-9]+\t0$' \
  "$RELEASE_GATE_TIMING_FILE" \
  || fail "successful parallel phase was not recorded"

started_at="$(( $(date +%s) - 3 ))"
release_gate_timing_write_run_diagnostic 7 "$started_at" 1800
node - "$RELEASE_GATE_RUN_DIAGNOSTIC" <<'NODE'
const { readFileSync } = require('node:fs')
const value = JSON.parse(readFileSync(process.argv[2], 'utf8'))
if (
  value.schema !== 1
  || value.outcome !== 'failed'
  || value.exitStatus !== 7
  || value.elapsedSeconds < 3
  || value.targetSeconds !== 1800
) process.exit(1)
NODE

# Exercise the actual entry point in a separate checkout: the enclosing gate
# owns its checkout lock while running this preflight regression harness.
fixture_root="$tmp/checkout"
mkdir -p "$fixture_root/scripts"
for script in "$ROOT_DIR"/scripts/*; do
  ln -s "$script" "$fixture_root/scripts/$(basename "$script")"
done
git -C "$fixture_root" init -q
printf 'artifacts/\nscripts/\n' >"$fixture_root/.gitignore"
git -C "$fixture_root" add .gitignore
git -C "$fixture_root" -c user.name=Fixture -c user.email=fixture@example.invalid \
  commit --allow-empty -qm fixture
failed_run_dir="$tmp/failed-run"
if env \
  NVPN_RELEASE_GATE_LOG_DIR="$failed_run_dir" \
  NVPN_RELEASE_GATE_REQUIRE_COMPLETE=invalid \
  "$fixture_root/scripts/release-gate.sh" \
  >"$tmp/failed-run.out" 2>"$tmp/failed-run.err"
then
  fail "invalid complete-mode preflight unexpectedly passed"
else
  status="$?"
fi
[[ "$status" -eq 2 ]] || fail "release preflight exit status changed"
node - "$failed_run_dir/release-gate-run.json" <<'NODE'
const { readFileSync } = require('node:fs')
const value = JSON.parse(readFileSync(process.argv[2], 'utf8'))
if (value.outcome !== 'failed' || value.exitStatus !== 2) process.exit(1)
NODE
grep -Eq '^serial\tComplete release mode preflight\t[0-9]+\t[0-9]+\t[0-9]+\t2$' \
  "$failed_run_dir/release-gate-timings.tsv" \
  || fail "failed release preflight was not written to the timing ledger"

printf 'release gate timing harness passed\n'
