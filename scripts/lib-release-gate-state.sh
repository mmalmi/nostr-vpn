#!/usr/bin/env bash

RELEASE_GATE_STATE_DIR=""
RELEASE_GATE_STATE_TOOL="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/release-gate-state.mjs"

release_gate_state_init() {
  RELEASE_GATE_STATE_DIR="$(node "$RELEASE_GATE_STATE_TOOL" init "$1" "$$")"
}

release_gate_state_phase() {
  [[ -n "$RELEASE_GATE_STATE_DIR" ]] || return 0
  node "$RELEASE_GATE_STATE_TOOL" phase "$RELEASE_GATE_STATE_DIR" "$@"
}

release_gate_checkpoint_run() {
  local label="$1" action
  shift
  [[ -n "$RELEASE_GATE_STATE_DIR" ]] || { "$@"; return; }
  action="$(node "$RELEASE_GATE_STATE_TOOL" checkpoint "$RELEASE_GATE_STATE_DIR" "$label" begin)"
  if [[ "$action" == reuse ]]; then
    printf 'Reusing validated check for unchanged inputs: %s\n' "$label"
    return 0
  fi
  # A plain command preserves errexit inside shell functions.
  "$@"
  node "$RELEASE_GATE_STATE_TOOL" checkpoint "$RELEASE_GATE_STATE_DIR" "$label" finish >/dev/null
}
