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
if release_gate_timing_run failure bash -c 'exit 7'; then
  fail "failed phase was masked"
else
  status="$?"
fi
[[ "$status" -eq 7 ]] || fail "failed phase exit status changed"

grep -Eq '^serial\tsuccess\t[0-9]+\t[0-9]+\t[0-9]+\t0$' \
  "$RELEASE_GATE_TIMING_FILE" \
  || fail "successful serial phase was not recorded"
grep -Eq '^serial\tfailure\t[0-9]+\t[0-9]+\t[0-9]+\t7$' \
  "$RELEASE_GATE_TIMING_FILE" \
  || fail "failed serial phase was not recorded"

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

failed_run_dir="$tmp/failed-run"
if env \
  NVPN_RELEASE_GATE_LOG_DIR="$failed_run_dir" \
  NVPN_RELEASE_GATE_REQUIRE_COMPLETE=invalid \
  "$ROOT_DIR/scripts/release-gate.sh" \
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
