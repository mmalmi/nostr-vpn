#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
fixture="$(mktemp -d "${TMPDIR:-/tmp}/nvpn-late-join.XXXXXX")"
trap 'rm -rf "$fixture"' EXIT

python3 - "$ROOT/scripts/macos-vm-release-mobile-join-e2e.sh" "$fixture/direction.sh" <<'PY'
from pathlib import Path
import sys
source = Path(sys.argv[1]).read_text()
start = source.index("set +e\n(\nset -euo pipefail\nMACOS_MOBILE_DIRECTION_LABEL=macos-admin-iphone-joiner")
end = source.index("\nmacos_admin_ios_status=$?", start)
Path(sys.argv[2]).write_text(source[start:end] + "\n")
PY

for completed_ms in 14000 16001; do
  RESULT_DIR="$fixture/$completed_ms"
  mkdir -p "$RESULT_DIR/macos"
  trace="$RESULT_DIR/trace"
  RELEASE_JOIN_DELIVERY_WAIT_SECS=15
  RELEASE_JOIN_IOS_SETUP_WAIT_SECS=60
  RELEASE_JOIN_UI_WAIT_SECS=60
  macos_mobile_direction_cleanup() { echo cleanup >>"$trace"; }
  prepare_macos_mobile_direction() { :; }
  macos_mobile_direction_child_owner() { echo owned; }
  release_join_valid_npub() { :; }
  marker_value() {
    case "$2" in
      NVPN_RELEASE_JOIN_ADMIN_ID) echo admin ;;
      NVPN_RELEASE_JOIN_NETWORK_ID) echo fresh ;;
    esac
  }
  ios_log() { echo "$RESULT_DIR/macos/ios.log"; }
  release_join_ios_start_test() { RELEASE_JOIN_IOS_TEST_PID=1; }
  release_join_ios_wait_marker() {
    [[ "$1" != NVPN_RELEASE_JOIN_ROSTER_APPLIED_MS= ]] \
      || echo "capture-timeout:$2" >>"$trace"
  }
  ios_marker_value_from() {
    case "$2" in
      NVPN_RELEASE_JOIN_JOINER_ID) echo joiner ;;
      NVPN_RELEASE_JOIN_RELAUNCH_DURABLE) echo admin ;;
    esac
  }
  remote() { echo "remote:$1" >>"$trace"; }
  wait_log_marker() { :; }
  release_join_now_ms() {
    if [[ -e "$RESULT_DIR/clock" ]]; then
      echo "$completed_ms"
    else
      touch "$RESULT_DIR/clock"
      echo 1000
    fi
  }
  assert_delivery_deadline() { (($2 - $1 <= 15000)); }
  release_join_signal_ios_peer_accepted() { echo peer-accepted >>"$trace"; }
  release_join_ios_finish_test() { echo relaunch-verified >>"$trace"; }

  source "$fixture/direction.sh"
  status=$?
  set -e
  expected=0
  ((completed_ms - 1000 <= 15000)) || expected=1
  [[ "$status" == "$expected" ]]
  grep -Fxq capture-timeout:30 "$trace"
  grep -Fxq peer-accepted "$trace"
  grep -Fxq relaunch-verified "$trace"
  grep -Fxq remote:verify "$trace"
  grep -Fxq cleanup "$trace"
done
python3 - "$ROOT/scripts/macos-vm-release-mobile-join-e2e.sh" "$fixture/reverse.sh" <<'PY'
from pathlib import Path
import sys
source = Path(sys.argv[1]).read_text()
start = source.index("set +e\n(\nset -euo pipefail\nMACOS_MOBILE_DIRECTION_LABEL=iphone-admin-macos-joiner")
end = source.index("\nios_admin_macos_status=$?", start)
Path(sys.argv[2]).write_text(source[start:end] + "\n")
PY

for completed_ms in 15000 16001; do
  RESULT_DIR="$fixture/reverse-$completed_ms"
  mkdir -p "$RESULT_DIR/macos"
  trace="$RESULT_DIR/trace"
  prepare_macos_mobile_direction() { :; }
  ios_create_admin() { RELEASE_JOIN_IOS_ADMIN_ID=admin; RELEASE_JOIN_IOS_NETWORK_ID=network; }
  marker_value() { echo joiner; }
  ios_marker_value_from() {
    case "$2" in
      NVPN_RELEASE_JOIN_APPROVAL_SUBMITTED_MS) echo 1000 ;;
      NVPN_RELEASE_JOIN_ROSTER_APPLIED_MS) echo 4000 ;;
      NVPN_RELEASE_JOIN_ADMIN_RELAUNCH_DURABLE) echo joiner ;;
    esac
  }
  release_join_ios_wait_marker() { :; }
  wait_log_marker() {
    if [[ "$2" == NVPN_RELEASE_JOIN_ROSTER_PARTICIPANT=admin ]]; then
      echo "capture-timeout:$3" >>"$trace"
      [[ "$3" == 30 ]] || return 1
    fi
  }
  assert_delivery_duration() { (($1 >= 0 && $1 <= 15000)); }
  finish_remote() { echo remote-finished >>"$trace"; }
  source "$fixture/reverse.sh"
  status=$?
  set -e
  expected=0
  ((completed_ms - 1000 <= 15000)) || expected=1
  [[ "$status" == "$expected" ]]
  grep -Fxq capture-timeout:30 "$trace"
  grep -Fxq peer-accepted "$trace"
  grep -Fxq relaunch-verified "$trace"
  grep -Fxq remote-finished "$trace"
  grep -Fxq remote:verify "$trace"
  grep -Fxq cleanup "$trace"
done
echo MACOS_LATE_JOIN_OBSERVATION_HARNESS_OK
