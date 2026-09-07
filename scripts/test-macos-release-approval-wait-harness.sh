#!/usr/bin/env bash
# Exercise the real coordinator without launching an app or contacting a device.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fixture="$(mktemp -d "${TMPDIR:-/tmp}/nvpn-approval-wait.XXXXXX")"
trap 'rm -rf "$fixture"' EXIT

# Extract the production function, not a second implementation of its timer.
eval "$(sed -n '/^run_manual_join_driver_hold() {$/,/^}$/p' \
  "$ROOT/scripts/macos-release-mobile-join-remote.sh")"

run_case() (
  local approval_after="$1" expected="$2"
  APPROVAL_STARTED="$fixture/approval-started"
  NVPN_RELEASE_JOIN_IOS_SETUP_WAIT_SECS="${3:-90}"
  unset SECONDS
  SECONDS=0
  verified=0
  stopped=0
  launch_app() { :; }
  run_driver_against_held_app() {
    if [[ "$1" == release-verify ]]; then
      [[ -f "$APPROVAL_STARTED" ]]
      verified=1
    fi
    return 0
  }
  stop_app() { stopped=1; }
  sleep() {
    SECONDS=$((SECONDS + 1))
    if ((approval_after > 0 && SECONDS == approval_after)); then
      touch "$APPROVAL_STARTED"
    fi
  }
  local status=0
  run_manual_join_driver_hold fixture-admin fixture-name || status=$?
  if [[ "$expected" == accepted ]]; then
    [[ "$status" -eq 0 && "$verified" -eq 1 && "$stopped" -eq 1 ]] || {
      echo "Mac stopped before bounded iPhone launch/setup could submit approval ($approval_after seconds)" >&2
      exit 1
    }
  else
    [[ "$status" -ne 0 && "$verified" -eq 0 \
      && "$SECONDS" -le $((60 + NVPN_RELEASE_JOIN_IOS_SETUP_WAIT_SECS)) ]] || {
      echo "Mac accepted without approval or waited beyond the setup budget" >&2
      exit 1
    }
  fi
)

# The old 30-second holder failed while real iOS setup was still typing.
run_case 61 accepted
run_case 149 accepted
run_case 0 rejected
run_case 151 rejected
run_case 62 accepted 3
run_case 64 rejected 3
if ! grep -Fq 'NVPN_RELEASE_JOIN_IOS_SETUP_WAIT_SECS=%q' \
    "$ROOT/scripts/macos-vm-release-mobile-join-e2e.sh"; then
  echo "Controller does not forward its validated setup budget" >&2
  exit 1
fi
echo "macOS approval setup wait harness passed"
