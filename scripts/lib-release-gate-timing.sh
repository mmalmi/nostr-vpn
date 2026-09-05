#!/usr/bin/env bash

RELEASE_GATE_TIMING_FILE=""
RELEASE_GATE_RUN_DIAGNOSTIC=""
RELEASE_GATE_TIMING_ACTIVE_LABEL=""
RELEASE_GATE_TIMING_ACTIVE_STARTED_AT=""

release_gate_timing_init() {
  local log_dir="$1" temporary
  [[ -n "$log_dir" ]] || return 2
  mkdir -p "$log_dir"
  RELEASE_GATE_TIMING_FILE="$log_dir/release-gate-timings.tsv"
  RELEASE_GATE_RUN_DIAGNOSTIC="$log_dir/release-gate-run.json"
  temporary="$RELEASE_GATE_TIMING_FILE.tmp.$$"
  (
    umask 077
    printf 'kind\tlabel\tstarted_at_epoch\tfinished_at_epoch\tduration_seconds\texit_status\n' \
      >"$temporary"
  )
  mv -f "$temporary" "$RELEASE_GATE_TIMING_FILE"
}

release_gate_timing_record() {
  local kind="$1" label="$2" started_at="$3" finished_at="$4" status="$5"
  local duration
  [[ -n "$RELEASE_GATE_TIMING_FILE" ]] || return 0
  [[ "$kind" != *$'\t'* && "$kind" != *$'\n'* \
    && "$label" != *$'\t'* && "$label" != *$'\n'* ]] || return 2
  [[ "$started_at" =~ ^[0-9]+$ && "$finished_at" =~ ^[0-9]+$ \
    && "$status" =~ ^[0-9]+$ ]] || return 2
  ((finished_at >= started_at)) || return 2
  duration=$((finished_at - started_at))
  printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$kind" "$label" "$started_at" "$finished_at" "$duration" "$status" \
    >>"$RELEASE_GATE_TIMING_FILE"
}

release_gate_timing_run() {
  local label="$1"
  shift
  local finished_at
  [[ -z "$RELEASE_GATE_TIMING_ACTIVE_LABEL" ]] || return 2
  RELEASE_GATE_TIMING_ACTIVE_LABEL="$label"
  RELEASE_GATE_TIMING_ACTIVE_STARTED_AT="$(date +%s)"
  if type release_gate_state_phase >/dev/null 2>&1; then
    release_gate_state_phase "$label" running
  fi
  # Keep this as a plain command. Wrapping it in `if` or `||` disables Bash's
  # fail-fast behavior inside shell functions and can mask an early failure.
  "$@"
  finished_at="$(date +%s)"
  release_gate_timing_record \
    serial "$label" "$RELEASE_GATE_TIMING_ACTIVE_STARTED_AT" \
    "$finished_at" 0 || return 1
  if type release_gate_state_phase >/dev/null 2>&1; then
    release_gate_state_phase "$RELEASE_GATE_TIMING_ACTIVE_LABEL" passed
  fi
  RELEASE_GATE_TIMING_ACTIVE_LABEL=""
  RELEASE_GATE_TIMING_ACTIVE_STARTED_AT=""
}

release_gate_timing_finish_active() {
  local status="$1" finished_at
  [[ -n "$RELEASE_GATE_TIMING_ACTIVE_LABEL" ]] || return 0
  finished_at="$(date +%s)"
  release_gate_timing_record \
    serial "$RELEASE_GATE_TIMING_ACTIVE_LABEL" \
    "$RELEASE_GATE_TIMING_ACTIVE_STARTED_AT" "$finished_at" "$status" \
    || return 1
  if type release_gate_state_phase >/dev/null 2>&1; then
    release_gate_state_phase "$RELEASE_GATE_TIMING_ACTIVE_LABEL" failed "$status"
  fi
  RELEASE_GATE_TIMING_ACTIVE_LABEL=""
  RELEASE_GATE_TIMING_ACTIVE_STARTED_AT=""
}

release_gate_timing_write_run_diagnostic() {
  local status="$1" started_at="$2" target_seconds="$3"
  local finished_at elapsed outcome temporary
  [[ -n "$RELEASE_GATE_RUN_DIAGNOSTIC" ]] || return 0
  [[ "$status" =~ ^[0-9]+$ && "$started_at" =~ ^[0-9]+$ \
    && "$target_seconds" =~ ^[0-9]+$ ]] || return 2
  finished_at="$(date +%s)"
  ((finished_at >= started_at)) || return 2
  elapsed=$((finished_at - started_at))
  if ((status == 0)); then
    outcome=passed
  else
    outcome=failed
  fi
  temporary="$RELEASE_GATE_RUN_DIAGNOSTIC.tmp.$$"
  (
    umask 077
    printf '{\n'
    printf '  "schema": 1,\n'
    printf '  "outcome": "%s",\n' "$outcome"
    printf '  "exitStatus": %d,\n' "$status"
    printf '  "startedAtEpoch": %d,\n' "$started_at"
    printf '  "finishedAtEpoch": %d,\n' "$finished_at"
    printf '  "elapsedSeconds": %d,\n' "$elapsed"
    printf '  "targetSeconds": %d\n' "$target_seconds"
    printf '}\n'
  ) >"$temporary"
  mv -f "$temporary" "$RELEASE_GATE_RUN_DIAGNOSTIC"
}
