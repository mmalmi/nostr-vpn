#!/usr/bin/env bash
# ShellCheck cannot see fixture callbacks invoked by sourced/extracted functions.
# shellcheck disable=SC1090,SC1091,SC2030,SC2031,SC2034,SC2100,SC2153,SC2329
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

FILES=(
  "$ROOT/scripts/mobile-release-join-e2e.sh"
  "$ROOT/scripts/lib-mobile-release-join-artifacts.sh"
  "$ROOT/scripts/lib-mobile-release-artifact-reuse.sh"
  "$ROOT/scripts/lib-mobile-release-join-ui.sh"
  "$ROOT/scripts/lib-mobile-ios-release-artifact.sh"
  "$ROOT/scripts/macos-vm-release-mobile-join-e2e.sh"
  "$ROOT/scripts/macos-release-mobile-join-remote.sh"
  "$ROOT/scripts/ubuntu-vm-release-mobile-join-e2e.sh"
  "$ROOT/scripts/windows-vm-release-mobile-join-e2e.sh"
)
for file in "${FILES[@]}"; do
  bash -n "$file"
done
(
  dispatch="$(sed -n '/^case "$RELEASE_JOIN_PHASE_SELECTION" in$/,/^esac$/p' "$ROOT/scripts/mobile-release-join-e2e.sh")"
  RELEASE_JOIN_PHASE_SELECTION=qr-only
  phase_ios_admin_android_qr() { echo iphone-qr; }
  phase_android_admin_ios_qr() { echo pixel-qr; }
  release_join_ios_run_test() { echo unexpected-normalization; return 1; }
  [[ "$(eval "$dispatch")" == $'iphone-qr\npixel-qr' ]] || {
    echo 'QR-only dispatch did not select exactly both QR directions' >&2
    exit 1
  }
)
python3 - "$ROOT" <<'PY'
import pathlib,sys
root=pathlib.Path(sys.argv[1])
host=(root/'scripts/macos-vm-release-mobile-join-e2e.sh').read_text()
host=host.split('ios_join_log="$(ios_log macos-admin-iphone-join)"',1)[1].split('# Physical iPhone admin -> macOS joiner.',1)[0]
assert host.index('remote require-delivery-log') < host.index('release_join_signal_ios_peer_accepted') < host.index('release_join_ios_finish_test')
runner=(root/'ios/UITests/NostrVpnReleaseJoinUITests.swift').read_text()
runner=runner.split('func testManualJoinAndRequireRosterCompletion()',1)[1].split('func testManualAdminAddRequiresRosterProgress()',1)[0]
assert runner.index('relaunch: false') < runner.index('waitForPeerAcceptance(admin)') < runner.index('relaunchAndRequireAcceptedRoster')
assert 'NVPN_RELEASE_JOIN_PEER_ACCEPTED_FILENAME' in runner
PY
(
  # Exercise the real USB copy adapter with an external fixture executable.
  # Copying must neither launch the app nor depend on CoreDevice's active
  # XCTest connection, and a transfer failure must reach the caller.
  source "$ROOT/scripts/lib-mobile-release-join-ui.sh"
  private="$(mktemp -d "${TMPDIR:-/tmp}/nvpn-ios-usb-copy.XXXXXX")"
  trap 'rm -rf "$private"' EXIT
  mkdir "$private/bin"
  export PATH="$private/bin:$PATH"
  export NVPN_TEST_IOS_COPY_DIR="$private"
  IOS_DEVICE=fixture-device
  cat >"$private/bin/ios-deploy" <<'PY'
#!/usr/bin/env python3
import os,pathlib,sys,time
args=sys.argv[1:]
root=pathlib.Path(os.environ['NVPN_TEST_IOS_COPY_DIR'])
assert args[:5] == ['--id','fixture-device','--no-wifi','--bundle_id','fixture.runner']
if os.environ.get('NVPN_TEST_IOS_COPY_FAIL') == '1':sys.exit(7)
if os.environ.get('NVPN_TEST_IOS_COPY_FAIL') == 'timeout':
    (root/'copy.pid').write_text(str(os.getpid()))
    time.sleep(30)
if '--upload' in args:
    assert pathlib.Path(args[args.index('--upload')+1]).read_bytes() == b'fixture'
    assert args[args.index('--to')+1] == 'Documents/fixture.txt'
    (root/'uploaded').write_text('ok')
else:
    assert '--download=Documents/fixture.txt' in args
    dest=pathlib.Path(args[args.index('--to')+1])/'Documents/fixture.txt'
    dest.parent.mkdir(parents=True)
    dest.write_bytes(b'fixture')
PY
  chmod +x "$private/bin/ios-deploy"
  printf fixture >"$private/source"
  release_join_ios_copy_test_file to fixture.runner "$private/source" Documents/fixture.txt
  [[ -s "$private/uploaded" ]]
  release_join_ios_copy_test_file from fixture.runner Documents/fixture.txt "$private/downloaded"
  cmp "$private/source" "$private/downloaded"
  export NVPN_TEST_IOS_COPY_FAIL=1
  if release_join_ios_copy_test_file to fixture.runner "$private/source" Documents/fixture.txt; then
    echo 'USB copy failure was ignored' >&2
    exit 1
  fi
  export NVPN_TEST_IOS_COPY_FAIL=timeout
  started=$SECONDS
  if release_join_ios_copy_test_file to fixture.runner "$private/source" Documents/fixture.txt; then
    echo 'USB copy did not enforce its transfer deadline' >&2
    exit 1
  fi
  ((SECONDS - started < 19))
  if kill -0 "$(cat "$private/copy.pid")" 2>/dev/null; then
    echo 'Timed-out USB copy process was not reaped' >&2
    exit 1
  fi
)
(
  # A bounded unavailable/locked preflight must not launch XCTest. Once the
  # device is unlocked, method selection and authorization are still checked.
  source "$ROOT/scripts/lib-mobile-release-join-artifacts.sh"
  source "$ROOT/scripts/lib-mobile-release-join-ui.sh"
  source "$ROOT/scripts/lib-mobile-ios-release-network.sh"
  ios_release_network_require_unlocked() { :; }
  private="$(mktemp -d "${TMPDIR:-/tmp}/nvpn-ios-join-readiness.XXXXXX")"
  trap 'rm -rf "$private"' EXIT
  PRIVATE_DIR="$private"
  IOS_DEVICE=fixture-device
  RELEASE_JOIN_ARTIFACTS_VALIDATED=1
  RELEASE_JOIN_DEVICE_MUTATION_ALLOWED=1
  lock_available=0
  ios_release_network_require_unlocked() {
    printf 'checked\n' >>"$private/status-query"
    [[ "$lock_available" == 1 ]]
  }
  release_join_ios_stop_runner() { :; }
  release_join_ios_test_command() {
    if [[ "$1" == denied ]]; then
      printf '%s\0' bash -c 'echo "Timed out while enabling automation mode."; sleep 30'
    else
      printf '%s\0' bash -c \
        'printf "%s\n" "Test Case '\''-[NostrVpnIosUITests.NostrVpnReleaseJoinUITests fixture]'\'' started."; sleep 1'
    fi
  }
  if release_join_ios_run_test fixture "$private/ready.log"; then
    echo 'Unavailable lock preflight launched a test' >&2
    exit 1
  fi
  [[ ! -e "$private/ready.log" && "$RELEASE_JOIN_DEVICE_MUTATED" == 0 ]]
  lock_available=1
  release_join_ios_run_test fixture "$private/ready.log"
  authorization_started=$SECONDS
  if release_join_ios_run_test denied "$private/denied.log"; then
    echo 'iOS join accepted a pre-method authorization failure' >&2
    exit 1
  fi
  ((SECONDS - authorization_started < 5)) || {
    echo 'iOS join waited after Apple had already denied automation' >&2
    exit 1
  }
  [[ $(wc -l <"$private/status-query" | tr -d ' ') == 3 ]]

)
(
  source "$ROOT/scripts/lib-mobile-release-join-ui.sh"
  PRIVATE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/nvpn-join-snapshot.XXXXXX")"
  trap 'rm -rf "$PRIVATE_DIR"' EXIT
  ADB=(snapshot_adb)
  snapshot_adb() {
    [[ "$1" != shell ]] || return "$dump_status"
    printf 'read\n' >>"$PRIVATE_DIR/reads"
    printf '<hierarchy><node resource-id="accepted" bounds="[0,0][100,100]"/></hierarchy>'
  }
  # A previous accepted snapshot must not survive a failed fresh device dump.
  for dump_status in 0 7; do
    result=0
    release_join_android_query resource accepted center >/dev/null || result=$?
    if (( (dump_status == 0 && result != 0) || (dump_status != 0 && result == 0) )); then
      echo 'Android UI query accepted a stale snapshot or rejected a fresh one' >&2
      exit 1
    fi
  done
  [[ $(wc -l <"$PRIVATE_DIR/reads" | tr -d ' ') == 1 ]]
)
(
  source "$ROOT/scripts/lib-mobile-release-join-artifacts.sh"
  source "$ROOT/scripts/lib-mobile-release-join-ui.sh"
  tmp="$(mktemp -d "${TMPDIR:-/tmp}/nvpn-join-network-setup.XXXXXX")"
  trap 'rm -rf "$tmp"' EXIT
  RELEASE_JOIN_UI_WAIT_SECS=2
  RELEASE_JOIN_ARTIFACTS_VALIDATED=1
  NVPN_RELEASE_JOIN_REUSE_ARTIFACTS=1
  trace() { printf '%s\n' "$*" >>"$tmp/calls"; }
  ADB=(trace)
  release_join_android_stop() { trace stop; }
  release_join_android_launch() { trace launch; }
  release_join_android_dump_ui() {
    trace dump
    RELEASE_JOIN_ANDROID_UI_XML="$tmp/ui.xml"
    # Dialog accessibility exposes descriptions without resource IDs.
    if [[ "$scenario" == fresh ]]; then
      printf '<hierarchy><node text="" resource-id="" content-desc="Create Network" bounds="[0,0][100,100]"/></hierarchy>' >"$RELEASE_JOIN_ANDROID_UI_XML"
    else
      printf '<hierarchy><node><node clickable="true" bounds="[0,0][100,100]"><node text="Saved network"/></node><node checkable="true"><node content-desc="Turn VPN on"/></node></node></hierarchy>' >"$RELEASE_JOIN_ANDROID_UI_XML"
    fi
  }
  release_join_android_wait_query() { trace "wait:$1:$2"; }
  release_join_android_tap_center() { trace "tap:$1:$2"; }
  release_join_android_tap_visible() { trace "tap:$1:$2"; }
  release_join_android_scroll_to() { trace "scroll:$1:$2"; }
  release_join_android_normalize_carrier() { trace normalize-carrier; }
  release_join_android_query() {
    [[ "$1:$2" == 'text:This device' && "$scenario" == saved-direct ]]
  }
  # Even navigation must not run before exact-artifact validation arms the device.
  if release_join_android_open_network_setup; then
    echo 'Android setup navigation ignored device ownership' >&2
    exit 1
  fi
  [[ ! -e "$tmp/calls" ]]
  RELEASE_JOIN_DEVICE_MUTATION_ALLOWED=1
  for scenario in fresh saved-wireguard saved-direct; do
    : >"$tmp/calls"
    release_join_android_open_network_setup
    [[ "$(head -2 "$tmp/calls" | tr '\n' ' ')" == 'stop launch ' ]]
    forbidden='clear|uninstall|delete|reset'
    if [[ "$scenario" != fresh ]]; then
      grep -Fxq normalize-carrier "$tmp/calls"
      [[ $(grep -n normalize-carrier "$tmp/calls" | cut -d: -f1) -lt $(grep -n 'tap:text:Add network' "$tmp/calls" | cut -d: -f1) ]]
      grep -Fxq 'tap:description:Internet tab' "$tmp/calls"
      if [[ "$scenario" == saved-wireguard ]]; then
        grep -Fxq 'tap:description:Internet source This device' "$tmp/calls"
        [[ $(grep -n 'tap:description:Internet source This device' "$tmp/calls" | cut -d: -f1) -lt $(grep -n 'tap:text:Add network' "$tmp/calls" | cut -d: -f1) ]]
      else
        forbidden+='|Internet source This device'
      fi
      grep -Fxq 'tap:network-picker:Turn VPN ' "$tmp/calls"
      grep -Fxq 'scroll:text:Add network' "$tmp/calls"
      grep -Fxq 'tap:text:Add network' "$tmp/calls"
      grep -Fxq 'wait:description:Create Network' "$tmp/calls"
    else
      ! grep -Fxq normalize-carrier "$tmp/calls"
      forbidden+='|^tap:'
    fi
    if grep -Eq "$forbidden" "$tmp/calls"; then
      echo 'Android setup made an unnecessary or destructive change' >&2
      exit 1
    fi
  done
)
(
  source "$ROOT/scripts/lib-mobile-release-join-ui.sh"
  PRIVATE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/nvpn-join-stop.XXXXXX")"
  trap 'rm -rf "$PRIVATE_DIR"' EXIT
  ADB=(cleanup_adb -s selected-test-device)
  cleanup_adb() {
    printf '%s\n' "$@" >>"$PRIVATE_DIR/adb-arguments"
    case "${FAKE_STOP_RESULT:-stopped}" in
      stopped) printf 'ACTIVITY MANAGER SERVICES\n  (nothing)\n' ;;
      active) printf 'ServiceRecord{123 selected-test-package/.NostrVpnService}\n' ;;
      ambiguous) printf 'query unavailable\n' ;;
      offline) return 7 ;;
    esac
  }
  # An iOS-only mutation must not grant ownership of Android cleanup.
  RELEASE_JOIN_DEVICE_MUTATED=1
  RELEASE_JOIN_ANDROID_MUTATED=0
  release_join_android_stop
  [[ ! -e "$PRIVATE_DIR/adb-arguments" ]]
  RELEASE_JOIN_ANDROID_MUTATED=1
  NVPN_DEFAULT_APP_ID=selected-test-package
  release_join_android_stop
  [[ "$(head -2 "$PRIVATE_DIR/adb-arguments" | tr '\n' ' ')" == '-s selected-test-device ' ]]
  grep -Fxq selected-test-package "$PRIVATE_DIR/adb-arguments"
  grep -Fxq force-stop "$PRIVATE_DIR/adb-arguments"
  grep -Fxq dumpsys "$PRIVATE_DIR/adb-arguments"
  grep -Fxq services "$PRIVATE_DIR/adb-arguments"
  if grep -Eq 'clear|uninstall|reboot' "$PRIVATE_DIR/adb-arguments"; then
    echo "Android cleanup attempted destructive recovery" >&2
    exit 1
  fi
  for FAKE_STOP_RESULT in active ambiguous offline; do
    if release_join_android_stop; then
      echo "Android cleanup accepted $FAKE_STOP_RESULT state" >&2
      exit 1
    fi
  done
  # The shared deadline runner is exercised with a real blocked child below.
  # Here test only this caller's five-second budget and timeout propagation.
  release_join_now_ms() { printf '1000\n'; }
  release_join_run_until_ms() {
    printf '%s\n' "$1" >"$PRIVATE_DIR/deadline"
    return 124
  }
  if release_join_android_stop; then
    echo "Android cleanup accepted a stalled device command" >&2
    exit 1
  fi
  [[ "$(<"$PRIVATE_DIR/deadline")" == 6000 ]]
)
(
  # Exercise the actual desktop cleanup functions, not just their text.
  PRIVATE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/nvpn-join-cleanup-trap.XXXXXX")"
  trap 'rm -rf "$PRIVATE_DIR"' EXIT
  for join_driver in ubuntu windows macos; do
    for entry_status in 0 7; do
      for stop_status in 0 1; do
        result=0
        (
          RESULT_DIR="$PRIVATE_DIR"
          PLATFORM_RESULT="$PRIVATE_DIR"
          mkdir -p "$RESULT_DIR/macos" "$PRIVATE_DIR/state"
          PRIVATE_DIR="$PRIVATE_DIR/state"
          remote_pid="" REMOTE_ACTION_PID="" import_ready=0
          acceptance_observer_pids=()
          MACOS_MOBILE_DIRECTION_LABEL=fixture
          remote() { :; }
          ubuntu_vm_cleanup_imported_release_bundle() { :; }
          release_join_android_capture_failure_log() { :; }
          release_join_android_stop() {
            printf 'stop\n' >>"$RESULT_DIR/calls"
            return "$stop_status"
          }
          if [[ "$join_driver" == macos ]]; then
            eval "$(sed -n '/^macos_mobile_direction_cleanup() {$/,/^}$/p' "$ROOT/scripts/macos-vm-release-mobile-join-e2e.sh")"
            trap macos_mobile_direction_cleanup EXIT
          else
            eval "$(sed -n '/^cleanup() {$/,/^}$/p' "$ROOT/scripts/$join_driver-vm-release-mobile-join-e2e.sh")"
            trap cleanup EXIT
          fi
          exit "$entry_status"
        ) || result=$?
        [[ -s "$PRIVATE_DIR/calls" ]]
        rm "$PRIVATE_DIR/calls"
        if ((entry_status != 0)); then
          [[ "$result" -eq "$entry_status" ]]
        elif ((stop_status != 0)); then
          [[ "$result" -ne 0 ]]
        else
          [[ "$result" -eq 0 ]]
        fi
      done
    done
  done
)
(
  source "$ROOT/scripts/lib-mobile-release-join-ui.sh"
  PRIVATE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/nvpn-join-failure-log.XXXXXX")"
  trap 'rm -rf "$PRIVATE_DIR"' EXIT
  ADB=(failure_log_adb -s selected-test-device)
  failure_log_adb() {
    printf '%s\n' "$@" >"$PRIVATE_DIR/adb-arguments"
    if [[ "$3 $4 $5" == 'exec-out screencap -p' ]]; then
      printf 'failure-screen\n'
      return "${FAKE_ADB_RESULT:-0}"
    fi
    printf 'retained service lifecycle log\n'
    return "${FAKE_ADB_RESULT:-0}"
  }
  RELEASE_JOIN_ANDROID_MUTATED=0
  release_join_android_capture_failure_log "$PRIVATE_DIR/not-selected.log"
  [[ ! -e "$PRIVATE_DIR/not-selected.log" && ! -e "$PRIVATE_DIR/adb-arguments" ]]
  RELEASE_JOIN_ANDROID_MUTATED=1
  release_join_android_capture_failure_log "$PRIVATE_DIR/selected.log"
  grep -Fxq 'failure-screen' "$PRIVATE_DIR/selected.log.png"
  [[ "$(head -2 "$PRIVATE_DIR/adb-arguments" | tr '\n' ' ')" == '-s selected-test-device ' ]]
  grep -Fxq NostrVpnService:I "$PRIVATE_DIR/adb-arguments"
  grep -Fxq '*:S' "$PRIVATE_DIR/adb-arguments"
  grep -Fq 'retained service lifecycle log' "$PRIVATE_DIR/selected.log"
  FAKE_ADB_RESULT=7
  release_join_android_capture_failure_log "$PRIVATE_DIR/offline.log"
  grep -Fq 'status 7' "$PRIVATE_DIR/offline.log.stderr"
  release_join_android_capture_failure_log "$PRIVATE_DIR/missing/output.log"
  # Diagnostics must not abort cleanup or replace the original failure code.
  release_join_now_ms() { printf '1000\n'; }
  release_join_run_until_ms() {
    printf '%s\n' "$1" >"$PRIVATE_DIR/deadline"
    return 124
  }
  release_join_android_capture_failure_log "$PRIVATE_DIR/stalled.log"
  grep -Fq 'status 124' "$PRIVATE_DIR/stalled.log.stderr"
  [[ "$(<"$PRIVATE_DIR/deadline")" == 6000 ]]
)
for join_driver in \
  mobile-release-join-e2e.sh \
  macos-vm-release-mobile-join-e2e.sh \
  ubuntu-vm-release-mobile-join-e2e.sh \
  windows-vm-release-mobile-join-e2e.sh
do
  grep -Fq 'release_join_android_capture_failure_log ' "$ROOT/scripts/$join_driver"
done
for join_driver in \
  mobile-release-join-e2e.sh \
  macos-vm-release-mobile-join-e2e.sh \
  ubuntu-vm-release-mobile-join-e2e.sh \
  windows-vm-release-mobile-join-e2e.sh
do
  grep -Fq 'NVPN_RELEASE_JOIN_UI_WAIT_SECS:-30' \
    "$ROOT/scripts/$join_driver" \
    || { echo "$join_driver has a short public-UI readiness wait" >&2; exit 1; }
  grep -Fq 'NVPN_RELEASE_JOIN_DELIVERY_WAIT_SECS:-15' \
    "$ROOT/scripts/$join_driver" \
    || { echo "$join_driver weakened the 15-second delivery deadline" >&2; exit 1; }
done
grep -Fq 'NVPN_RELEASE_JOIN_IOS_SETUP_WAIT_SECS:-90' \
  "$ROOT/scripts/mobile-release-join-e2e.sh"
grep -Fq 'RELEASE_JOIN_IOS_SETUP_WAIT_SECS <= 90' \
  "$ROOT/scripts/mobile-release-join-e2e.sh"
grep -Fq 'NVPN_RELEASE_JOIN_IOS_SETUP_WAIT_SECS:-90' \
  "$ROOT/scripts/macos-vm-release-mobile-join-e2e.sh"
grep -Fq 'RELEASE_JOIN_IOS_SETUP_WAIT_SECS <= 90' \
  "$ROOT/scripts/macos-vm-release-mobile-join-e2e.sh"
grep -Fq 'testNormalizeRetainedJoinCarrierSettings' \
  "$ROOT/scripts/mobile-release-join-e2e.sh"
grep -Fq 'NVPN_RELEASE_JOIN_BOOTSTRAP_CONNECTED=' \
  "$ROOT/ios/UITests/NostrVpnReleaseJoinUITests.swift"
for setting in \
  connectToNonRosterFipsPeers \
  fipsNostrDiscoveryEnabled \
  fipsWebrtcEnabled \
  fipsBootstrapEnabled
do
  grep -Fq "\"$setting\"," "$ROOT/ios/Sources/AppModel.swift"
done
join_ui="$ROOT/scripts/lib-mobile-release-join-ui.sh"

python3 - \
  "$ROOT/ios/Sources/SettingsViews.swift" \
  "$ROOT/ios/UITests/NostrVpnReleaseJoinUITests.swift" <<'PY'
import pathlib
import sys

settings, tests = [pathlib.Path(path).read_text(encoding="utf-8") for path in sys.argv[1:]]
fips = settings.split("struct FipsSettingsCard: View", 1)[1].split(
    "struct PubsubSettingsCard: View", 1
)[0]
if fips.count(".disabled(model.actionInFlight)") != 4:
    raise SystemExit("FIPS controls do not all reject taps during VPN reconciliation")
setter = tests.split("private func setSwitchOn", 1)[1].split(
    "private func nonNegativeIntegerValue", 1
)[0]
if "control.exists && control.isEnabled" not in setter:
    raise SystemExit("physical iOS join test taps FIPS controls before reconciliation finishes")
if "control.coordinate(withNormalizedOffset:" not in setter:
    raise SystemExit("physical iOS join test does not target the iOS 26 switch control")

join_gate = pathlib.Path(sys.argv[2]).parents[2].joinpath(
    "scripts/mobile-release-join-e2e.sh"
).read_text(encoding="utf-8")
build_only = join_gate.find("SIGNED_RELEASE_JOIN_ARTIFACTS_READY")
if not (
    join_gate.find("release_join_prepare_ios_release")
    < build_only
    < join_gate.find("carrier_preflight_log=")
):
    raise SystemExit("mobile join build-only exit is not between artifact preparation and UI execution")

release_gate = pathlib.Path(sys.argv[2]).parents[2].joinpath(
    "scripts/release-gate.sh"
).read_text(encoding="utf-8")
mobile_gate = release_gate.split("run_mobile_join_e2e_gate()", 1)[1].split(
    "run_windows_release_mobile_join_e2e_gate()", 1
)[0]
variant_build = mobile_gate.find("NVPN_RELEASE_JOIN_BUILD_ONLY=1")
xctestrun_selection = mobile_gate.find("select_generated_ios_release_xctestrun")
if variant_build < 0 or not (variant_build < xctestrun_selection):
    raise SystemExit("release gate does not build the exact iOS join variant before reuse")
PY

(
  # Launch and in-test setup each receive their own bounded allowance.
  # shellcheck disable=SC1090,SC1091
  source "$join_ui"
  tmp="$(mktemp -d "${TMPDIR:-/tmp}/nvpn-ios-launch-budget.XXXXXX")"
  trap 'kill "${RELEASE_JOIN_IOS_TEST_PID:-}" >/dev/null 2>&1 || true; wait "${RELEASE_JOIN_IOS_TEST_PID:-}" >/dev/null 2>&1 || true; rm -rf "$tmp"' EXIT
  RELEASE_JOIN_IOS_TEST_LOG="$tmp/runner.log"
  RELEASE_JOIN_IOS_TEST_NAME="testFixture"
  (
    sleep 0.2
    printf '%s\n' \
      "Test Case '-[NostrVpnIosUITests.NostrVpnReleaseJoinUITests testFixture]' started." \
      >>"$RELEASE_JOIN_IOS_TEST_LOG"
    sleep 0.2
    printf '%s\n' \
      'NVPN_RELEASE_JOIN_MARKER NVPN_RELEASE_JOIN_QR_READY=1' \
      >>"$RELEASE_JOIN_IOS_TEST_LOG"
    sleep 0.2
  ) &
  RELEASE_JOIN_IOS_TEST_PID=$!
  release_join_ios_wait_selected_test_started 2
  release_join_ios_wait_marker NVPN_RELEASE_JOIN_QR_READY=1 2
)

(
  # The trusted XCTest runner capture must be copied by exact filename/hash.
  # shellcheck disable=SC1091
  source "$join_ui"
  private="$(mktemp -d "${TMPDIR:-/tmp}/nvpn-ios-qr-capture.XXXXXX")"
  trap 'rm -rf "$private"' EXIT
  PRIVATE_DIR="$private"
  IOS_DEVICE=fixture-device
  RELEASE_JOIN_IOS_TEST_LOG="$private/runner.log"
  captured="$private/captured.png"
  printf '\211PNG\r\n\032\nfixture' >"$captured"
  capture_sha="$(shasum -a 256 "$captured" | awk '{print $1}')"
  cat >"$RELEASE_JOIN_IOS_TEST_LOG" <<EOF
NVPN_RELEASE_JOIN_MARKER NVPN_RELEASE_JOIN_QR_SCREENSHOT_FILENAME=nvpn-release-join-qr-ABC123.png
NVPN_RELEASE_JOIN_MARKER NVPN_RELEASE_JOIN_QR_SCREENSHOT_SHA256=$capture_sha
EOF
  release_join_ios_copy_test_file() {
    [[ "$1" == from && "$2" == fi.siriusbusiness.nvpn.UITests.xctrunner ]]
    [[ "$3" == Documents/nvpn-release-join-qr-ABC123.png && -n "$4" ]]
    cp "$captured" "$4"
  }
  release_join_capture_ios_qr "$private/qr.png"
  [[ "$(od -An -tx1 -N8 "$private/qr.png" | tr -d ' \n')" \
    == 89504e470d0a1a0a ]]
  [[ "$(shasum -a 256 "$private/qr.png" | awk '{print $1}')" == "$capture_sha" ]]
)
(
  # Only the separately receipted join-test app exposes a Files container.
  # Production metadata and the retained XCTest runner remain unchanged.
  # shellcheck disable=SC1091
  source "$ROOT/scripts/lib-mobile-release-join-artifacts.sh"
  tmp="$(mktemp -d "${TMPDIR:-/tmp}/nvpn-ios-fixture-files.XXXXXX")"
  trap 'rm -rf "$tmp"' EXIT
  PRIVATE_DIR="$tmp/private"
  app="$tmp/Nostr VPN.app"
  mkdir -p "$PRIVATE_DIR" "$app"
  plutil -create xml1 "$app/Info.plist"
  plutil -insert CFBundleIdentifier \
    -string fixture.join.app "$app/Info.plist"
  for key in UIFileSharingEnabled LSSupportsOpeningDocumentsInPlace; do
    if plutil -extract "$key" raw "$ROOT/ios/Info.plist" >/dev/null 2>&1; then
      exit 1
    fi
  done
  codesign() {
    local argument prefix=""
    printf '%s\n' "$*" >>"$tmp/codesign.log"
    for argument in "$@"; do
      [[ "$argument" != --extract-certificates=* ]] \
        || prefix="${argument#--extract-certificates=}"
    done
    [[ -z "$prefix" ]] || printf 'fixture certificate\n' >"${prefix}0"
  }
  release_join_expose_ios_fixture_documents "$app"
  [[ "$(plutil -extract CFBundleDisplayName raw "$app/Info.plist")" \
    == "Nostr VPN Test Files" ]]
  [[ "$(plutil -extract UIFileSharingEnabled raw "$app/Info.plist")" \
    == true ]]
  [[ "$(plutil -extract LSSupportsOpeningDocumentsInPlace raw \
    "$app/Info.plist")" == true ]]
  grep -Eq -- \
    '--force --sign [0-9a-f]{40} --preserve-metadata=identifier,entitlements,requirements,flags,runtime' \
    "$tmp/codesign.log"
  grep -Fq -- '--verify --deep --strict' "$tmp/codesign.log"
)
(
  # The visible app and runner hash-binding containers receive the same image.
  # shellcheck disable=SC1091
  source "$join_ui"
  private="$(mktemp -d "${TMPDIR:-/tmp}/nvpn-ios-dual-qr-stage.XXXXXX")"
  trap 'rm -rf "$private"' EXIT
  PRIVATE_DIR="$private"
  IOS_DEVICE=fixture-device
  image="$private/fixture.png"
  printf '\211PNG\r\n\032\nfixture' >"$image"
  release_join_ios_copy_test_file() {
    printf '%s\n' "$*" >>"$private/copy.log"
    [[ "$1" == to && -n "$2" && "$3" == "$image" && "$4" == Documents/fixture.png ]]
  }
  release_join_stage_ios_qr_image "$image" fixture.png
  [[ "$(grep -c '^to ' "$private/copy.log")" == 2 ]]
  grep -Fq -- 'to fi.siriusbusiness.nvpn ' "$private/copy.log"
  grep -Fq -- \
    'to fi.siriusbusiness.nvpn.UITests.xctrunner ' \
    "$private/copy.log"
)
python3 -B "$ROOT/scripts/macos_release_join_artifact.py" --help >/dev/null

(
  set -u
  # shellcheck disable=SC1091
  source "$ROOT/scripts/lib-mobile-release-join-ui.sh"
  RELEASE_JOIN_UI_WAIT_SECS=1
  release_join_android_query() { return 1; }
  release_join_android_os_vpn_connected() { return 0; }
  release_join_android_wait_vpn_connected
) || {
  echo "Android carrier readiness incorrectly depends on an on-screen toggle" >&2
  exit 1
}

python3 - \
  "$ROOT/scripts/mobile-release-join-e2e.sh" \
  "$ROOT/scripts/macos-vm-release-mobile-join-e2e.sh" \
  "$ROOT/scripts/ubuntu-vm-release-mobile-join-e2e.sh" \
  "$ROOT/scripts/windows-vm-release-mobile-join-e2e.sh" <<'PY'
import pathlib
import sys

for name in sys.argv[1:]:
    source = pathlib.Path(name).read_text(encoding="utf-8")
    parts = source.split("release_join_android_manual_submit")
    if len(parts) != 2:
        raise SystemExit(f"{pathlib.Path(name).name} must have one Android manual-join phase")
    following = parts[1]
    wait = following.find("release_join_android_wait_vpn_connected")
    if wait < 0:
        raise SystemExit(
            f"{pathlib.Path(name).name} approves before the Android join carrier is ready"
        )
    approval_markers = [
        following.find(token)
        for token in ("release_join_ios_start_test", "remote admin-add", "remote AdminAdd")
        if following.find(token) >= 0
    ]
    if not approval_markers or wait > min(approval_markers):
        raise SystemExit(
            f"{pathlib.Path(name).name} starts approval before the Android join carrier is ready"
        )
PY

(
  set -u
  # shellcheck disable=SC1091
  source "$ROOT/scripts/lib-mobile-release-join-artifacts.sh"
  private="$(mktemp -d "${TMPDIR:-/tmp}/nvpn-ios-join-cleanup.XXXXXX")"
  trap 'rm -rf "$private"' EXIT
  PRIVATE_DIR="$private"
  RESULT_DIR="$private"
  RELEASE_JOIN_IOS_XCTESTRUN="$private/fixture.xctestrun"
  RELEASE_JOIN_IOS_QUARANTINE="$private/quarantine"
  NVPN_DEFAULT_IOS_BUNDLE_ID="fixture.join.bundle"
  printf 'fixture\n' >"$RELEASE_JOIN_IOS_XCTESTRUN"
  unset IOS_BUNDLE_ID
  ios_release_network_disconnect_cleanup() {
    [[ "$IOS_BUNDLE_ID" == "$NVPN_DEFAULT_IOS_BUNDLE_ID" ]]
  }
  ios_release_network_require_packet_tunnel_stopped() { return 1; }
  release_join_arm_ios_disconnect_cleanup \
    "$private/Nostr VPN.app" "$private/derived" fixture-device
  release_join_cleanup_ios_network_state
  [[ ! -e "$RELEASE_JOIN_IOS_QUARANTINE" ]]
)

(
  source "$ROOT/scripts/lib-mobile-release-join-ui.sh"
  release_join_android_launch() { :; }
  release_join_android_query() { return 1; }
  release_join_android_wait_query() { [[ "$*" == "description Devices tab" ]]; }
  release_join_android_tap() { [[ "$*" == "description Devices tab" ]]; }
  release_join_android_open_devices
)

(
  source "$ROOT/scripts/lib-mobile-release-join-ui.sh"
  release_join_android_dump_ui() { :; }
  release_join_android_query_dumped() { return 0; }
  [[ "$(release_join_android_accepted_snapshot_ms npub1accepted)" =~ ^[0-9]+$ ]]
)

(
  # shellcheck disable=SC1091
  source "$ROOT/scripts/lib-mobile-release-join-artifacts.sh"
  fake_adb() {
    case "$*" in
      "shell pm list packages") printf '%s\n' "$FAKE_ANDROID_PACKAGES" ;;
      "shell pm path fi.siriusbusiness.nvpn") return 0 ;;
      *) return 1 ;;
    esac
  }
  ADB=(fake_adb)
  FAKE_ANDROID_PACKAGES=$'package:fi.siriusbusiness.nvpn\npackage:fi.siriusbusiness.nvpn.debug'
  if release_join_assert_one_android_package >/dev/null 2>&1; then
    echo "Android one-package check accepted a stale package" >&2
    exit 1
  fi
  FAKE_ANDROID_PACKAGES='package:fi.siriusbusiness.nvpn'
  release_join_assert_one_android_package
)

(
  # Exact-artifact reuse may explicitly retain both installed mobile apps.
  # shellcheck disable=SC1091
  source "$ROOT/scripts/lib-mobile-release-join-artifacts.sh"
  tmp="$(mktemp -d "${TMPDIR:-/tmp}/nvpn-join-noinstall.XXXXXX")"
  trap 'rm -rf "$tmp"' EXIT
  export NVPN_RELEASE_JOIN_REUSE_ARTIFACTS=1
  export NVPN_RELEASE_JOIN_INSTALL_ANDROID=0
  export NVPN_RELEASE_JOIN_INSTALL_IOS=0
  release_join_configure_install_modes
  [[ "$RELEASE_JOIN_INSTALL_ANDROID" -eq 0 \
    && "$RELEASE_JOIN_INSTALL_IOS" -eq 0 ]]
  NVPN_RELEASE_JOIN_REUSE_ARTIFACTS=0
  if release_join_configure_install_modes >"$tmp/no-reuse.log" 2>&1; then
    echo "mobile join accepted disabled installs without exact reuse" >&2
    exit 1
  fi
  grep -Fq 'requires exact artifact reuse' "$tmp/no-reuse.log"
  NVPN_RELEASE_JOIN_REUSE_ARTIFACTS=1
  NVPN_RELEASE_JOIN_INSTALL_IOS=maybe
  if release_join_configure_install_modes >"$tmp/bad-mode.log" 2>&1; then
    echo "mobile join accepted an ambiguous install mode" >&2
    exit 1
  fi
)

(
  # Cover reuse, replacement, and fresh installs through one real preparation path.
  # shellcheck disable=SC1091
  source "$ROOT/scripts/lib-mobile-release-join-artifacts.sh"
  tmp="$(mktemp -d "${TMPDIR:-/tmp}/nvpn-join-android-install.XXXXXX")"
  trap 'rm -rf "$tmp"' EXIT
  apk="$tmp/app-release.apk"
  printf 'exact installed apk\n' >"$apk"
  fake_adb() {
    printf '%s\n' "$*" >>"$tmp/adb.log"
    case "$*" in
      "shell pm path fi.siriusbusiness.nvpn")
        [[ "$installed" == true ]] || return 1
        printf 'package:/data/app/exact/base.apk\n'
        ;;
      "shell pm list packages") printf 'package:fi.siriusbusiness.nvpn\n' ;;
      "pull /data/app/exact/base.apk "*) cp "$apk" "$3" ;;
      "shell dumpsys package fi.siriusbusiness.nvpn") printf '  flags=[ HAS_CODE ]\n' ;;
      "shell pidof fi.siriusbusiness.nvpn") printf '1234\n' ;;
      "install -r "*) installed=true ;;
      *) : ;;
    esac
  }
  ADB=(fake_adb)
  RESULT_DIR="$tmp/result"
  PRIVATE_DIR="$tmp/private"
  mkdir -p "$PRIVATE_DIR"
  mkdir -p "$RESULT_DIR"
  RELEASE_JOIN_ARTIFACTS_VALIDATED=1
  RELEASE_JOIN_DEVICE_MUTATION_ALLOWED=1
  RELEASE_JOIN_ANDROID_APK="$apk"
  RELEASE_JOIN_ANDROID_APP_SHA="$(printf '1%.0s' {1..40})"
  RELEASE_JOIN_ANDROID_APP_TREE="$(printf '2%.0s' {1..40})"
  RELEASE_JOIN_ANDROID_SIGNER_SHA="$(printf 'a%.0s' {1..64})"
  RELEASE_JOIN_FIPS_SHA="$(printf '3%.0s' {1..40})"
  RELEASE_JOIN_FIPS_TREE="$(printf '4%.0s' {1..40})"
  APP_GIT_SHA="$RELEASE_JOIN_ANDROID_APP_SHA"
  APP_GIT_TREE="$RELEASE_JOIN_ANDROID_APP_TREE"
  NVPN_RELEASE_JOIN_REUSE_ARTIFACTS=1
  NVPN_RELEASE_JOIN_INSTALL_IOS=1
  release_join_assert_fips_unchanged() { :; }
  release_join_assert_app_unchanged() { :; }
  sleep() { :; }
  for scenario in '0 true 0' '1 true 1' '1 false 2'; do
    read -r NVPN_RELEASE_JOIN_INSTALL_ANDROID installed expected_installs <<<"$scenario"
    preexisting="$installed"
    : >"$tmp/adb.log"
    release_join_configure_install_modes
    release_join_prepare_android_release
    actual_installs="$(grep -c '^install -r ' "$tmp/adb.log" || true)"
    [[ "$actual_installs" -eq "$expected_installs" ]] || {
      echo "Android preparation made $actual_installs installs; expected $expected_installs ($scenario)" >&2
      exit 1
    }
    python3 - "$RESULT_DIR/android-release-install.json" "$preexisting" "$NVPN_RELEASE_JOIN_INSTALL_ANDROID" <<'PY'
import json, sys
r = json.load(open(sys.argv[1], encoding="utf-8"))
assert r["installedArtifactVerified"] is True
assert r["preexistingCanonicalPackage"] is (sys.argv[2] == "true")
assert r["replacementInstall"] is (sys.argv[3] == "1")
assert r["replacementInstallVerified"] is (sys.argv[3] == "1")
PY
  done
)

(
  # App replacement retains the trusted runner and verifies USB inventories.
  # shellcheck disable=SC1091
  source "$ROOT/scripts/lib-mobile-release-join-artifacts.sh"
  source "$ROOT/scripts/lib-mobile-ios-release-network.sh"
  ios_release_network_require_unlocked() { :; }
  tmp="$(mktemp -d "${TMPDIR:-/tmp}/nvpn-join-ios-noinstall.XXXXXX")"
  trap 'rm -rf "$tmp"' EXIT
  app="$tmp/Nostr VPN.app"
  runner="$tmp/derived/Build/Products/Release-iphoneos/NostrVpnIosUITests-Runner.app"
  mkdir -p "$app" "$runner" "$tmp/result"
  python3 - "$app/Info.plist" "$runner/Info.plist" <<'PY'
import plistlib, sys
for path, bundle, build, version in (
    (sys.argv[1], "fi.siriusbusiness.nvpn", "4001008", "4.1.5"),
    (sys.argv[2], "fi.siriusbusiness.nvpn.UITests.xctrunner", "1", "1.0"),
):
    with open(path, "wb") as f:
        plistlib.dump({"CFBundleIdentifier": bundle, "CFBundleVersion": build,
                       "CFBundleShortVersionString": version}, f)
PY
  : >"$tmp/devicectl.log"
  xcrun() {
    printf '%s\n' "$*" >>"$tmp/devicectl.log"
    [[ "$*" == *"device install app"* && "${ALLOW_APP_INSTALL:-0}" == 1 && "$*" == *" $app --quiet" ]]
  }
  mkdir -p "$tmp/bin"
  cat >"$tmp/bin/ios-deploy" <<'USB_FIXTURE'
#!/usr/bin/env python3
import json
import os
import sys
assert sys.argv[1:3] == ["--id", "fixture-hardware-udid"]
assert "--list_bundle_id" in sys.argv and "--json" in sys.argv
apps = {}
for bundle, build, version in (
    ("fi.siriusbusiness.nvpn", "4001008", "4.1.5"),
    ("fi.siriusbusiness.nvpn.UITests.xctrunner", "1", os.environ.get("FAKE_IOS_RUNNER_VERSION", "1.0")),
):
    apps[bundle] = {"CFBundleIdentifier": bundle, "CFBundleVersion": build, "CFBundleShortVersionString": version}
print(json.dumps({"Event": "ListBundleId", "Apps": apps}))
USB_FIXTURE
  chmod +x "$tmp/bin/ios-deploy"
  export PATH="$tmp/bin:$PATH"
  export FAKE_IOS_RUNNER_VERSION=1.0
  RESULT_DIR="$tmp/result"
  IOS_DEVICE=fixture-hardware-udid
  RELEASE_JOIN_ARTIFACTS_VALIDATED=1
  RELEASE_JOIN_DEVICE_MUTATION_ALLOWED=1
  RELEASE_JOIN_INSTALL_IOS=0
  RELEASE_JOIN_FIPS_SHA="$(printf '3%.0s' {1..40})"
  RELEASE_JOIN_FIPS_TREE="$(printf '4%.0s' {1..40})"
  RELEASE_JOIN_FIPS_VERSION=1.2.3
  RELEASE_JOIN_IOS_XCTESTRUN="$tmp/exact.xctestrun"
  printf 'fixture\n' >"$RELEASE_JOIN_IOS_XCTESTRUN"
  RELEASE_JOIN_IOS_QUARANTINE="$tmp/ios.quarantine"
  NVPN_RELEASE_JOIN_IOS_INSTALL_RECEIPT="$tmp/device-bound-ios-install-receipt.json"
  runner_tree="$(
    python3 "$ROOT/scripts/mobile_release_artifact_receipt.py" tree-sha "$runner"
  )"
  python3 - \
    "$NVPN_RELEASE_JOIN_IOS_INSTALL_RECEIPT" fixture-hardware-udid \
    "$runner_tree" <<'PY'
import hashlib, json, sys
json.dump({
    "receiptSchema": 1,
    "artifactType": "installed iOS Release app and XCTest runner",
    "appGitSha": "1" * 40,
    "appGitTree": "2" * 40,
    "fipsGitSha": "3" * 40,
    "fipsGitTree": "4" * 40,
    "bundleManifestSha256": "a" * 64,
    "runnerBundleTreeSha256": sys.argv[3],
    "signerCertificateSha256": "c" * 64,
    "selectedPhysicalDeviceIdentifierSha256": hashlib.sha256(
        sys.argv[2].encode()
    ).hexdigest(),
    "bundleIdentifier": "fi.siriusbusiness.nvpn",
    "installedVersion": "4001008",
    "installedShortVersion": "4.1.5",
}, open(sys.argv[1], "w"))
PY
  release_join_install_ios_release \
    "$app" "$(printf '1%.0s' {1..40})" "$(printf '2%.0s' {1..40})" \
    "$(printf 'a%.0s' {1..64})" "$(printf 'b%.0s' {1..64})" \
    "$(printf 'c%.0s' {1..64})" "$tmp/derived" fixture-hardware-udid
  if grep -Fq 'device install app' "$tmp/devicectl.log"; then
    echo "iOS exact-artifact reuse unexpectedly installed an app" >&2
    exit 1
  fi
  python3 - "$RESULT_DIR/ios-release-install.json" <<'PY'
import json, sys
r = json.load(open(sys.argv[1], encoding="utf-8"))
assert r["installedArtifactVerified"] is True
assert r["replacementInstall"] is False
assert r["installedVersion"] == "4001008"
assert r["installedShortVersion"] == "4.1.5"
assert r["runnerBundleTreeSha256"]
assert r["selectedPhysicalDeviceIdentifierSha256"]
PY
  cp "$NVPN_RELEASE_JOIN_IOS_INSTALL_RECEIPT" "$tmp/device-bound-ios-receipt.clean"
  python3 - "$NVPN_RELEASE_JOIN_IOS_INSTALL_RECEIPT" <<'PY'
import json, pathlib, sys
path = pathlib.Path(sys.argv[1])
value = json.loads(path.read_text())
value["selectedPhysicalDeviceIdentifierSha256"] = "0" * 64
path.write_text(json.dumps(value))
PY
  if release_join_install_ios_release \
      "$app" "$(printf '1%.0s' {1..40})" "$(printf '2%.0s' {1..40})" \
      "$(printf 'a%.0s' {1..64})" "$(printf 'b%.0s' {1..64})" \
      "$(printf 'c%.0s' {1..64})" "$tmp/derived" fixture-hardware-udid \
      >"$tmp/device-receipt-mismatch.log" 2>&1
  then
    echo "iOS no-install reuse accepted another phone's install receipt" >&2
    exit 1
  fi
  grep -Fq 'device-bound iOS receipt mismatch' \
    "$tmp/device-receipt-mismatch.log"
  mv "$tmp/device-bound-ios-receipt.clean" "$NVPN_RELEASE_JOIN_IOS_INSTALL_RECEIPT"
  cp "$NVPN_RELEASE_JOIN_IOS_INSTALL_RECEIPT" "$tmp/device-bound-ios-receipt.clean"
  python3 - "$NVPN_RELEASE_JOIN_IOS_INSTALL_RECEIPT" <<'PY'
import json, pathlib, sys
path = pathlib.Path(sys.argv[1])
value = json.loads(path.read_text())
value["runnerBundleTreeSha256"] = "0" * 64
path.write_text(json.dumps(value))
PY
  if release_join_install_ios_release \
      "$app" "$(printf '1%.0s' {1..40})" "$(printf '2%.0s' {1..40})" \
      "$(printf 'a%.0s' {1..64})" "$(printf 'b%.0s' {1..64})" \
      "$(printf 'c%.0s' {1..64})" "$tmp/derived" fixture-hardware-udid \
      >"$tmp/runner-receipt-mismatch.log" 2>&1
  then
    echo "iOS no-install reuse accepted another runner binary" >&2
    exit 1
  fi
  grep -Fq 'device-bound iOS receipt mismatch' \
    "$tmp/runner-receipt-mismatch.log"
  mv "$tmp/device-bound-ios-receipt.clean" "$NVPN_RELEASE_JOIN_IOS_INSTALL_RECEIPT"
  plutil -replace CFBundleShortVersionString -string 2.0 "$runner/Info.plist"
  if release_join_install_ios_release \
      "$app" 1 2 3 4 5 "$tmp/derived" fixture-hardware-udid \
      >"$tmp/runner-mismatch.log" 2>&1
  then
    echo "iOS no-install reuse accepted a mismatched installed runner" >&2
    exit 1
  fi
  grep -Fq 'installed iOS bundle version mismatch' "$tmp/runner-mismatch.log"

  # Switching to the separately signed QR variant must retain a proven runner.
  source "$ROOT/scripts/lib-mobile-ios-release-network.sh"
  ios_release_network_require_unlocked() { :; }
  plutil -replace CFBundleShortVersionString -string 1.0 "$runner/Info.plist"
  # The join path owns its bundle selection, not the packet-gate caller's globals.
  IOS_BUNDLE_ID=unrelated.native.app
  unset IOS_RELEASE_NETWORK_DEVICE IOS_RELEASE_NETWORK_SIGNING_DIR
  PRIVATE_DIR="$tmp"
  RELEASE_JOIN_IOS_CLEANUP_ARMED=0
  RELEASE_JOIN_INSTALL_IOS=1
  NVPN_RELEASE_JOIN_IOS_RECEIPT="$tmp/variant.json"
  printf '%s\n' '{"installedBuildNumber":"4001008","installedMarketingVersion":"4.1.5"}' \
    >"$NVPN_RELEASE_JOIN_IOS_RECEIPT"
  NVPN_MOBILE_IOS_INSTALLED_RUNNER_RECEIPT="$tmp/installed-runner.json"
  ios_release_network_write_runner_install_receipt \
    "$runner" "$NVPN_MOBILE_IOS_INSTALLED_RUNNER_RECEIPT" "$runner_tree" \
    "$(printf %s fixture-hardware-udid | shasum -a 256 | awk '{print $1}')" \
    "$(release_join_sha256 "$RELEASE_JOIN_IOS_XCTESTRUN")" \
    "$(python3 "$ROOT/scripts/mobile_release_artifact_receipt.py" tree-sha "$tmp/derived/Build/Products")"
  ALLOW_APP_INSTALL=1
  : >"$tmp/devicectl.log"
  release_join_install_ios_release \
    "$app" "$(printf '1%.0s' {1..40})" "$(printf '2%.0s' {1..40})" \
    "$(printf 'a%.0s' {1..64})" "$(printf 'b%.0s' {1..64})" \
    "$(printf 'c%.0s' {1..64})" "$tmp/derived" fixture-hardware-udid
  [[ "$(grep -Fc 'device install app' "$tmp/devicectl.log")" == 1 ]] \
    || { echo "join variant replaced the verified installed runner" >&2; exit 1; }
  [[ "$IOS_BUNDLE_ID" == unrelated.native.app ]]
  printf '%s\n' '{}' >"$NVPN_MOBILE_IOS_INSTALLED_RUNNER_RECEIPT"
  : >"$tmp/devicectl.log"
  if release_join_install_ios_release \
      "$app" 1 2 3 4 5 "$tmp/derived" fixture-hardware-udid \
      >"$tmp/retained-runner-mismatch.log" 2>&1
  then
    echo "join variant accepted missing installed runner provenance" >&2
    exit 1
  fi
  if grep -Fq 'device install app' "$tmp/devicectl.log"; then
    echo "join variant changed the phone before validating retained runner provenance" >&2
    exit 1
  fi
)

(
  # shellcheck disable=SC1091
  source "$ROOT/scripts/lib-mobile-release-join-ui.sh"
  # shellcheck disable=SC1091
  source "$ROOT/scripts/lib-mobile-ios-release-network.sh"
  ios_release_network_require_unlocked() { :; }
  log="$(mktemp "${TMPDIR:-/tmp}/nvpn-ios-join-selection.XXXXXX")"
  trap 'rm -f "$log"' EXIT
  RELEASE_JOIN_IOS_TEST_LOG="$log"
  RELEASE_JOIN_IOS_TEST_NAME="testSelectedMethod"
  printf 'NVPN_RELEASE_JOIN_MARKER CRLF_VALUE=npub1fixture\r\n' >"$log"
  [[ "$(release_join_ios_marker_value CRLF_VALUE)" == "npub1fixture" ]]
  : >"$log"
  true &
  RELEASE_JOIN_IOS_TEST_PID=$!
  if release_join_ios_finish_test >/dev/null 2>&1; then
    echo "iOS join runner accepted an exit-0 zero-test run" >&2
    exit 1
  fi
  printf '%s\n' \
    "Test Case '-[NostrVpnIosUITests.NostrVpnReleaseJoinUITests testSelectedMethod]' started." \
    >"$log"
  RELEASE_JOIN_IOS_TEST_NAME="testSelectedMethod"
  true &
  RELEASE_JOIN_IOS_TEST_PID=$!
  release_join_ios_finish_test
)

(
  set -u
  # A failed concurrent phase must reap the whole host process group and stop
  # only the retained runner process on-device, without uninstalling it.
  source "$ROOT/scripts/lib-mobile-release-join-artifacts.sh"
  # shellcheck disable=SC1091
  source "$ROOT/scripts/lib-mobile-release-join-ui.sh"
  # shellcheck disable=SC1091
  source "$ROOT/scripts/lib-mobile-ios-release-network.sh"
  ios_release_network_require_unlocked() { :; }
  private="$(mktemp -d "${TMPDIR:-/tmp}/nvpn-ios-join-abort.XXXXXX")"
  trap 'rm -rf "$private"' EXIT
  PRIVATE_DIR="$private"
  IOS_DEVICE="fixture-device"
  unset IOS_BUNDLE_ID
  audit="$private/runner-audit"
  ios_release_network_stop_forced_xctrunner() {
    [[ "$IOS_BUNDLE_ID" == "fi.siriusbusiness.nvpn" ]]
    printf 'audited\n' >"$audit"
  }
  release_join_ios_test_command() {
    printf '%s\0' bash -c \
      'printf "%s\n" "Test Case '\''-[NostrVpnIosUITests.NostrVpnReleaseJoinUITests fixture]'\'' started."; sleep 30 & wait'
  }
  if release_join_ios_start_test fixture "$private/fixture.log"; then
    echo "iOS join test started before device mutation was armed" >&2
    exit 1
  fi
  [[ ! -e "$private/fixture.log" ]]
  RELEASE_JOIN_ARTIFACTS_VALIDATED=1
  RELEASE_JOIN_DEVICE_MUTATION_ALLOWED=1
  release_join_ios_start_test fixture "$private/fixture.log"
  pgid="$RELEASE_JOIN_IOS_TEST_PGID"
  release_join_ios_abort_test
  [[ -s "$audit" ]]
  if ios_release_network_process_group_alive "$pgid"; then
    echo "aborted iOS join test retained a process-group descendant" >&2
    exit 1
  fi
  [[ -z "$RELEASE_JOIN_IOS_TEST_PID" && -z "$RELEASE_JOIN_IOS_TEST_PGID" ]]
)

(
  # Even a failed isolation check must reap both the command's descendants and
  # any separately reported process group before returning.
  source "$ROOT/scripts/lib-mobile-release-join-artifacts.sh"
  RELEASE_JOIN_ARTIFACTS_VALIDATED=1
  RELEASE_JOIN_DEVICE_MUTATION_ALLOWED=1
  # shellcheck disable=SC1091
  source "$ROOT/scripts/lib-mobile-release-join-ui.sh"
  # shellcheck disable=SC1091
  source "$ROOT/scripts/lib-mobile-ios-release-network.sh"
  ios_release_network_require_unlocked() { :; }
  private="$(mktemp -d "${TMPDIR:-/tmp}/nvpn-ios-join-isolation.XXXXXX")"
  trap 'rm -rf "$private"' EXIT
  PRIVATE_DIR="$private"
  IOS_DEVICE="fixture-device"
  child_file="$private/child.pid"
  set -m
  (exec sleep 30) &
  unexpected_pgid=$!
  set +m
  ios_release_network_stop_forced_xctrunner() { :; }
  release_join_ios_test_command() {
    # shellcheck disable=SC2016
    printf '%s\0' bash -c 'sleep 30 & printf "%s\n" "$!" >"$1"; wait' \
      fixture "$child_file"
  }
  release_join_ios_process_pgid() {
    local deadline=$((SECONDS + 2))
    while [[ ! -s "$child_file" && "$SECONDS" -lt "$deadline" ]]; do
      sleep 0.01
    done
    printf '%s\n' "$unexpected_pgid"
  }
  if release_join_ios_start_test fixture "$private/fixture.log"; then
    echo "iOS join runner accepted unexpected process-group isolation" >&2
    exit 1
  fi
  child_pid="$(cat "$child_file")"
  if kill -0 "$child_pid" >/dev/null 2>&1 \
      || ios_release_network_process_group_alive "$unexpected_pgid"; then
    echo "isolation failure retained a spawned child or process group" >&2
    exit 1
  fi
  [[ -z "$RELEASE_JOIN_IOS_TEST_PID" && -z "$RELEASE_JOIN_IOS_TEST_PGID" ]]
)

(
  set -u
  # shellcheck disable=SC1091
  source "$ROOT/scripts/lib-mobile-release-join-ui.sh"
  calls="$(mktemp "${TMPDIR:-/tmp}/nvpn-android-create-admin.XXXXXX")"
  trap 'rm -f "$calls"' EXIT
  release_join_android_launch() { :; }
  release_join_android_wait_query() { :; }
  release_join_android_tap() { :; }
  release_join_android_accept_admin_transport_permissions() {
    echo transport-permissions >>"$calls"
  }
  release_join_android_wait_vpn_connected() {
    echo vpn-connected >>"$calls"
  }
  release_join_android_open_link_device() { :; }
  release_join_valid_npub() { :; }
  release_join_android_public_value() {
    case "$1" in
      "Admin Device ID value") printf '%s\n' npub1admin ;;
      "Admin Network ID value") printf '%s\n' network-1 ;;
      *) return 1 ;;
    esac
  }
  release_join_android_create_admin
  [[ "$RELEASE_JOIN_ANDROID_ADMIN_ID" == npub1admin ]]
  [[ "$RELEASE_JOIN_ANDROID_NETWORK_ID" == network-1 ]]
  ((${#RELEASE_JOIN_ANDROID_NETWORK_IDS[@]} == 1))
  grep -Fxq transport-permissions "$calls"
  grep -Fxq vpn-connected "$calls"
) || {
  echo "Android first network creation failed under Bash nounset" >&2
  exit 1
}

# Exercise the four real directional phase functions with resource-free drivers.
# This checks behavior without coupling the harness to their source layout.
(
  tmp="$(mktemp -d "${TMPDIR:-/tmp}/nvpn-mobile-join-phases.XXXXXX")"
  trap 'rm -rf "$tmp"' EXIT
  phase_source="$tmp/phases.sh"
  for name in \
    phase_ios_admin_android_qr \
    phase_android_admin_ios_qr \
    phase_ios_admin_android_manual \
    phase_android_admin_ios_manual
  do
    sed -n "/^$name() {/,/^}/p" \
      "$ROOT/scripts/mobile-release-join-e2e.sh"
  done >"$phase_source"
  # shellcheck disable=SC1090
  source "$phase_source"

  RESULT_DIR="$tmp/result"
  mkdir -p "$RESULT_DIR"
  ANDROID_QR_CAPTURE="$RESULT_DIR/android.png"
  IOS_QR_CAPTURE="$RESULT_DIR/ios.png"
  IOS_QR_STAGED_FILENAME=android.png
  RELEASE_JOIN_UI_WAIT_SECS=1
  RELEASE_JOIN_IMPORT_WAIT_SECS=1
  RELEASE_JOIN_IOS_SETUP_WAIT_SECS=1
  RELEASE_JOIN_DELIVERY_WAIT_SECS=1
  RELEASE_JOIN_QR_CONTENT_WIDTH_MIN_BPS=9800
  trace_file="$tmp/trace"

  trace() { printf '%s\n' "$*" >>"$trace_file"; }
  fail() { echo "$*" >&2; return 1; }
  ios_log() { printf '%s/%s.log\n' "$RESULT_DIR" "$1"; }
  release_join_now_ms() { trace clock; printf '1000\n'; }
  assert_delivery_deadline() {
    [[ "$1" =~ ^[0-9]+$ && "$2" =~ ^[0-9]+$ ]]
    trace "delivered:$3"
  }
  release_join_valid_npub() { [[ "$1" == npub1* ]]; }
  release_join_android_open_network_setup() { trace network-setup-android; }
  ios_create_admin() {
    RELEASE_JOIN_IOS_ADMIN_ID=npub1iosadmin
    RELEASE_JOIN_IOS_NETWORK_ID=ios-network
    trace ios-admin
  }
  release_join_android_create_admin() {
    RELEASE_JOIN_ANDROID_ADMIN_ID=npub1androidadmin
    RELEASE_JOIN_ANDROID_NETWORK_ID=android-network
    trace android-admin
  }
  release_join_android_show_qr() {
    RELEASE_JOIN_ANDROID_JOINER_ID=npub1androidjoiner
    trace android-qr-joiner
  }
  release_join_android_background_foreground_pending_qr() {
    RELEASE_JOIN_ANDROID_PENDING_QR_LIFECYCLE_READY=1
    trace android-background-foreground
  }
  release_join_capture_android_qr() {
    printf '\211PNG\r\n\032\nfixture' >"$1"
    trace capture-android-qr
  }
  release_join_capture_ios_qr() {
    printf '\211PNG\r\n\032\nfixture' >"$1"
    trace capture-ios-qr
  }
  release_join_stage_ios_qr_image() {
    [[ -s "$1" && "$2" == "$IOS_QR_STAGED_FILENAME" ]]
    trace stage-ios-qr
  }
  release_join_ios_start_test() {
    active_test="$1"
    : >"$2"
    trace "ios-test:$active_test"
  }
  release_join_ios_run_test() {
    [[ "$1" == testNormalizeRetainedJoinCarrierSettings ]]
    trace ios-carrier-prepared
  }
  release_join_ios_wait_marker() {
    trace "ios-marker:$1"
  }
  release_join_ios_finish_test() { trace "ios-finish:$active_test"; }
  release_join_signal_ios_peer_accepted() {
    [[ "$1" == nvpn-peer-accepted-*.txt && "$2" == npub1androidjoiner ]]
    trace ios-peer-accepted
  }
  ios_marker_value_from() {
    case "$2" in
      NVPN_RELEASE_JOIN_JOINER_ID) printf '%s\n' npub1iosjoiner ;;
      NVPN_RELEASE_JOIN_APPROVAL_SUBMITTED_MS) trace approval-clock; printf '900\n' ;;
      NVPN_RELEASE_JOIN_ROSTER_APPLIED_MS) printf '1000\n' ;;
      NVPN_RELEASE_JOIN_QR_RELAUNCH_DURABLE) printf '%s\n' "$RELEASE_JOIN_ANDROID_ADMIN_ID" ;;
      NVPN_RELEASE_JOIN_QR_CONTENT_WIDTH_BPS) printf '9900\n' ;;
      NVPN_RELEASE_JOIN_ADMIN_RELAUNCH_DURABLE) printf '%s\n' "$RELEASE_JOIN_ANDROID_JOINER_ID" ;;
      NVPN_RELEASE_JOIN_RELAUNCH_DURABLE) printf '%s\n' "$RELEASE_JOIN_ANDROID_ADMIN_ID" ;;
      *) return 1 ;;
    esac
  }
  release_join_android_assert_pending_qr() { trace android-qr-pending; }
  release_join_android_wait_qr_join_complete() {
    [[ "$2" == 1900 && "$3" == "$RESULT_DIR/iphone-admin-pixel-qr-observations.tsv" ]]
    trace "android-qr-accepted:$1"
    printf '1000\n'
  }
  release_join_android_relaunch_and_wait_accepted() { trace "android-relaunch-accepted:$1"; }
  release_join_android_scan_prepare() { trace android-scan-ready; }
  release_join_android_scan_submit() {
    [[ -s "$2" ]]
    trace "android-scan-accepted:$1"
    echo 'NVPN_RELEASE_JOIN_MARKER NVPN_RELEASE_JOIN_APPROVAL_SUBMITTED_MS=1000'
  }
  release_join_android_manual_submit() {
    [[ "$1" == npub1iosadmin && "$2" == ios-network ]]
    RELEASE_JOIN_ANDROID_JOINER_ID=npub1androidjoiner
    trace android-manual-joiner
  }
  release_join_android_wait_vpn_connected() {
    trace android-vpn-connected
  }
  release_join_android_open_devices() {
    echo "Pending manual join must not reopen or navigate the app" >&2
    return 1
  }
  release_join_android_wait_query() {
    [[ "$1" == resource && "$2" == roster-participant-pending-npub1iosadmin ]]
    trace android-devices-ready
  }
  release_join_observe_until_ms() {
    [[ "$1" == 1900 && "$4" == release_join_android_accepted_snapshot_ms ]]
    trace "android-manual-accepted:$5"
    printf '1000\n' >"$2"
  }
  release_join_android_manual_admin_prepare() { trace "android-admin-prepared:$1"; }
  release_join_android_manual_admin_tap() {
    trace "android-admin-submitted:$1"
    echo 'NVPN_RELEASE_JOIN_MARKER NVPN_RELEASE_JOIN_APPROVAL_SUBMITTED_MS=1000'
  }

  : >"$trace_file"
  phase_ios_admin_android_qr
  grep -Fxq ios-admin "$trace_file"
  grep -Fxq android-background-foreground "$trace_file"
  qr_carrier_line="$(grep -n -m1 '^android-vpn-connected$' "$trace_file" | cut -d: -f1)"
  qr_approval_line="$(grep -n -m1 '^ios-test:' "$trace_file" | cut -d: -f1)"
  [[ -n "$qr_carrier_line" && -n "$qr_approval_line" ]]
  ((qr_carrier_line < qr_approval_line))
  grep -Fxq stage-ios-qr "$trace_file"
  pending_line="$(grep -n -m1 '^android-qr-pending$' "$trace_file" | cut -d: -f1)"
  stage_line="$(grep -n -m1 '^stage-ios-qr$' "$trace_file" | cut -d: -f1)"
  clock_line="$(grep -n -m1 '^approval-clock$' "$trace_file" | cut -d: -f1)"
  approval_line="$(grep -n -m1 '^ios-marker:NVPN_RELEASE_JOIN_APPROVAL_SUBMITTED_MS=$' "$trace_file" | cut -d: -f1)"
  ((pending_line < stage_line)) || {
    echo "Pending QR check raced approval after staging the image" >&2
    exit 1
  }
  ((stage_line < qr_approval_line)) || {
    echo "QR image transfer competed with an active XCTest runner" >&2
    exit 1
  }
  ((approval_line < clock_line)) || {
    echo "QR delivery clock did not use the actual approval marker" >&2
    exit 1
  }
  grep -Fxq 'android-qr-accepted:npub1iosadmin' "$trace_file"
  grep -Fxq 'android-relaunch-accepted:npub1iosadmin' "$trace_file"

  : >"$trace_file"
  phase_android_admin_ios_qr
  carrier_line="$(grep -n -m1 '^ios-carrier-prepared$' "$trace_file" | cut -d: -f1)"
  pending_line="$(grep -n -m1 '^ios-test:testShowPhysicalJoinQrAndRequireRosterCompletion$' "$trace_file" | cut -d: -f1)"
  [[ -n "$carrier_line" && -n "$pending_line" ]]
  ((carrier_line < pending_line)) || {
    echo "Reverse QR join began without preparing its public carrier" >&2
    exit 1
  }
  grep -Fxq android-admin "$trace_file"
  grep -Fxq android-scan-ready "$trace_file"
  grep -Fxq 'android-scan-accepted:npub1iosjoiner' "$trace_file"
  grep -Fxq 'ios-finish:testShowPhysicalJoinQrAndRequireRosterCompletion' "$trace_file"
  [[ "$RELEASE_JOIN_IOS_QR_RELAUNCH_DURABLE" == 1 \
    && "$RELEASE_JOIN_IOS_QR_CONTENT_WIDTH_BPS" == 9900 ]]

  : >"$trace_file"
  phase_ios_admin_android_manual
  grep -Fxq android-manual-joiner "$trace_file"
  accepted_line="$(grep -n -m1 '^android-manual-accepted:' "$trace_file" | cut -d: -f1)"
  signal_line="$(grep -n -m1 '^ios-peer-accepted$' "$trace_file" | cut -d: -f1)"
  relaunch_line="$(grep -n -m1 '^android-relaunch-accepted:' "$trace_file" | cut -d: -f1)"
  ((accepted_line < signal_line && signal_line < relaunch_line)) || {
    echo 'Admin relaunch was permitted before peer acceptance or after tearing down the peer' >&2
    exit 1
  }
  ready_line="$(grep -n -m1 '^android-devices-ready$' "$trace_file" | cut -d: -f1 || true)"
  approval_line="$(grep -n -m1 '^ios-test:' "$trace_file" | cut -d: -f1)"
  if [[ -z "$ready_line" || -z "$approval_line" ]] || ((ready_line >= approval_line)); then
    echo "Android manual-join delivery observer navigated after approval" >&2
    exit 1
  fi
  grep -Fxq 'android-manual-accepted:npub1iosadmin' "$trace_file"
  grep -Fxq 'ios-finish:testManualAdminAddRequiresRosterProgress' "$trace_file"
  [[ "$RELEASE_JOIN_IOS_ADMIN_MANUAL_RELAUNCH_DURABLE" == 1 ]]

  : >"$trace_file"
  phase_android_admin_ios_manual
  grep -Fxq android-admin "$trace_file"
  grep -Fxq 'android-admin-prepared:npub1iosjoiner' "$trace_file"
  grep -Fxq 'android-admin-submitted:npub1iosjoiner' "$trace_file"
  grep -Fxq 'ios-finish:testManualJoinAndRequireRosterCompletion' "$trace_file"
  [[ "$RELEASE_JOIN_IOS_JOINER_MANUAL_RELAUNCH_DURABLE" == 1 ]]
)

# Run the Android QR lifecycle helper itself: Home, foreground, same request,
# pending QR, and width must all survive.
(
  # shellcheck disable=SC1091
  source "$ROOT/scripts/lib-mobile-release-join-ui.sh"
  tmp="$(mktemp -d "${TMPDIR:-/tmp}/nvpn-mobile-join-lifecycle.XXXXXX")"
  trap 'rm -rf "$tmp"' EXIT
  RELEASE_JOIN_ANDROID_JOINER_ID=npub1samejoiner
  ADB=(fake_adb)
  fake_adb() { printf '%s\n' "$*" >>"$tmp/adb"; }
  sleep() { :; }
  release_join_android_launch() { echo launch >>"$tmp/actions"; }
  release_join_android_scroll_to() { echo scroll >>"$tmp/actions"; }
  release_join_android_assert_pending_qr() { echo pending >>"$tmp/actions"; }
  release_join_android_assert_qr_full_width() { echo width >>"$tmp/actions"; }
  release_join_android_public_value() { printf '%s\n' npub1samejoiner; }
  release_join_android_background_foreground_pending_qr >/dev/null
  grep -Fxq 'shell input keyevent KEYCODE_HOME' "$tmp/adb"
  [[ "$(tr '\n' ' ' <"$tmp/actions")" == 'launch scroll pending width ' ]]
  [[ "$RELEASE_JOIN_ANDROID_PENDING_QR_LIFECYCLE_READY" == 1 ]]
)
(
  # A local pre-pairing listener is not yet a live approval carrier.
  listener_tmp="$(mktemp -d "${TMPDIR:-/tmp}/nvpn-macos-listener.XXXXXX")"
  trap 'rm -rf "$listener_tmp"' EXIT
  sed -n '/^assert_join_listener_ready() {/,/^}$/p' \
    "$ROOT/scripts/macos-release-mobile-join-remote.sh" >"$listener_tmp/functions.sh"
  source "$listener_tmp/functions.sh"
  CLI=listener_status
  CONFIG=fixture
  peer_count=0
  assert_service_ready() { :; }
  listener_status() {
    printf '{"expected_peer_count":0,"network_id":"fresh","daemon":{"running":true,"state":{"vpn_enabled":true,"vpn_active":false,"vpn_status":"Waiting for participants","fips_other_peer_count":%s}}}\n' "$peer_count"
  }
  sleep() { peer_count=2; }
  assert_join_listener_ready >/dev/null
  [[ "$peer_count" == 2 ]] || {
    echo "macOS listener was accepted before a carrier peer authenticated" >&2
    exit 1
  }
)
(
  profile_tmp="$(mktemp -d "${TMPDIR:-/tmp}/nvpn-macos-profile-swap.XXXXXX")"
  trap 'find "$profile_tmp" -depth -delete' EXIT
  functions_file="$profile_tmp/functions.sh"
  sed -n '/^swap_test_profile() {/,/^}$/p; /^restore_config_dir() {/,/^}$/p' \
    "$ROOT/scripts/macos-release-mobile-join-remote.sh" >"$functions_file"
  # shellcheck disable=SC1090
  source "$functions_file"
  CONFIG_DIR="$profile_tmp/Application Support/nvpn"
  PROFILE_STATE_DIR="$profile_tmp/profile-transaction"
  CONFIG_BACKUP="$PROFILE_STATE_DIR/prior"
  TEST_CONFIG_DIR="$PROFILE_STATE_DIR/test"
  TEST_PROFILE_MARKER="$PROFILE_STATE_DIR/state"
  mkdir -p "$CONFIG_DIR/unknown/nested"
  printf 'preserve-me\n' >"$CONFIG_DIR/unknown/nested/sentinel"
  swap_test_profile
  [[ -L "$CONFIG_DIR" && "$(readlink "$CONFIG_DIR")" == "$TEST_CONFIG_DIR" ]]
  printf 'test-only\n' >"$TEST_CONFIG_DIR/test-only"
  chmod 000 "$TEST_CONFIG_DIR/test-only"
  restore_config_dir
  grep -Fxq preserve-me "$CONFIG_DIR/unknown/nested/sentinel"
  [[ ! -L "$CONFIG_DIR" && ! -e "$TEST_CONFIG_DIR" && ! -e "$CONFIG_BACKUP" ]]
) || {
  echo "macOS canonical profile swap did not preserve unknown nested state" >&2
  exit 1
}

(
  source "$ROOT/scripts/lib-mobile-release-join-ui.sh"
  fake_qr_width=300
  fake_content_width=400

  release_join_android_dump_ui() { :; }
  release_join_android_query_dumped() {
    local kind="$1" expected="$2" output="$3"
    [[ "$output" == width ]] || return 1
    if [[ "$kind" == description && "$expected" == "Join request QR code" ]]; then
      printf '%s\n' "$fake_qr_width"
      return
    fi
    if [[ "$kind" == description && "$expected" == 'Join request QR content width' ]]; then
      printf '%s\n' "$fake_content_width"
      return
    fi
    return 1
  }

  if release_join_android_assert_qr_full_width 2>/dev/null; then
    echo "Android full-width gate accepted a 75% content-width QR" >&2
    exit 1
  fi
  fake_qr_width=396
  release_join_android_assert_qr_full_width || {
    echo "Android full-width gate rejected a 99% content-width QR" >&2
    exit 1
  }
  [[ "$RELEASE_JOIN_ANDROID_QR_CONTENT_WIDTH_BPS" == 9900 ]] || {
    echo "Android full-width gate did not record the observed content ratio" >&2
    exit 1
  }
  fake_qr_width=404
  if release_join_android_assert_qr_full_width 2>/dev/null; then
    echo "Android full-width gate accepted a QR wider than its content" >&2
    exit 1
  fi
)

(
  source "$ROOT/scripts/lib-mobile-release-join-ui.sh"
  RELEASE_JOIN_DELIVERY_WAIT_SECS=2
  RELEASE_JOIN_ANDROID_JOINER_ID=npub1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq
  roster_queries=0

  release_join_android_launch() { :; }
  release_join_android_dump_ui() { :; }
  release_join_android_query_dumped() {
    local kind="$1" expected="$2"
    if [[ "$kind" == resource && "$expected" == navigation-devices ]]; then
      return 0
    fi
    if [[ "$kind" == resource \
      && "$expected" == roster-participant-accepted-npub1admin ]]
    then
      roster_queries=$((roster_queries + 1))
      ((roster_queries >= 2))
      return
    fi
    return 1
  }

  declare -F release_join_android_wait_qr_join_complete >/dev/null \
    || {
      echo "Android Release join UI lacks the roster-backed QR completion waiter" >&2
      exit 1
    }
  if release_join_android_wait_qr_join_complete npub1admin 2>/dev/null; then
    echo "Android QR join accepted a roster that appeared after premature dismissal" >&2
    exit 1
  fi
  [[ "$roster_queries" == 1 ]] || {
    echo "Android QR join kept polling after the QR disappeared without its roster" >&2
    exit 1
  }
)

(
  source "$ROOT/scripts/lib-mobile-release-join-ui.sh"
  RELEASE_JOIN_DELIVERY_WAIT_SECS=1
  now=1000
  release_join_now_ms() { printf '%s\n' "$now"; }
  release_join_android_dump_ui() { now=2001; }
  release_join_android_query_dumped() { [[ "$1" == resource ]]; }
  if release_join_android_wait_qr_join_complete npub1admin 2000 >/dev/null; then
    echo "QR acceptance observed after the approval deadline incorrectly passed" >&2
    exit 1
  fi
)

(
  source "$ROOT/scripts/lib-mobile-release-join-ui.sh"
  RELEASE_JOIN_DELIVERY_WAIT_SECS=2
  RELEASE_JOIN_ANDROID_JOINER_ID=npub1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq
  snapshot=0
  launches=0

  release_join_android_launch() { launches=$((launches + 1)); }
  release_join_android_dump_ui() {
    snapshot=$((snapshot + 1))
  }
  release_join_android_query_dumped() {
    local kind="$1" expected="$2" output="$3"
    if ((snapshot == 1)); then
      if [[ "$kind" == description && "$expected" == "Join request QR code" ]]; then
        return 0
      fi
      if [[ "$kind" == description-prefix \
        && "$expected" == 'Joiner Device ID value: ' \
        && "$output" == description ]]
      then
        printf 'Joiner Device ID value: %s\n' "$RELEASE_JOIN_ANDROID_JOINER_ID"
        return 0
      fi
      return 1
    fi
    if [[ "$kind" == resource ]] \
      && [[ "$expected" == navigation-devices \
        || "$expected" == roster-participant-accepted-npub1admin ]]
    then
      return 0
    fi
    return 1
  }
  sleep() { :; }

  release_join_android_wait_qr_join_complete npub1admin \
    || {
      echo "Android QR join rejected an atomic QR-to-exact-roster transition" >&2
      exit 1
    }
  [[ "$snapshot" == 2 ]] || {
    echo "Android QR join did not accept the first exact roster snapshot" >&2
    exit 1
  }
  [[ "$launches" == 0 ]] || {
    echo "Android QR delivery polling relaunched the foreground app" >&2
    exit 1
  }
)

(
  source "$ROOT/scripts/lib-mobile-release-join-ui.sh"
  RELEASE_JOIN_DELIVERY_WAIT_SECS=1
  accepted_queries=0

  release_join_android_launch() { :; }
  release_join_android_open_devices() { :; }
  release_join_android_query() {
    local kind="$1" expected="$2"
    if [[ "$kind" == resource && "$expected" == navigation-devices ]]; then
      return 0
    fi
    if [[ "$kind" == resource \
      && "$expected" == roster-participant-pending-npub1admin ]]
    then
      return 0
    fi
    if [[ "$kind" == resource \
      && "$expected" == roster-participant-accepted-npub1admin ]]
    then
      accepted_queries=$((accepted_queries + 1))
      return 1
    fi
    return 1
  }
  release_join_android_tap() { :; }
  sleep() { :; }

  if release_join_android_wait_accepted_participant npub1admin; then
    echo "Android manual join accepted a locally pending roster row" >&2
    exit 1
  fi
  ((accepted_queries > 0)) || {
    echo "Android manual join never queried the accepted-only roster selector" >&2
    exit 1
  }
)

(
  source "$ROOT/scripts/lib-mobile-release-join-ui.sh"
  RELEASE_JOIN_DELIVERY_WAIT_SECS=1

  release_join_android_launch() { :; }
  release_join_android_open_devices() { :; }
  release_join_android_query() {
    local kind="$1" expected="$2"
    [[ "$kind" == resource ]] \
      && [[ "$expected" == navigation-devices \
        || "$expected" == roster-participant-accepted-npub1admin ]]
  }
  release_join_android_tap() { :; }

  release_join_android_wait_accepted_participant npub1admin || {
    echo "Android manual join rejected the exact accepted roster row" >&2
    exit 1
  }
)

(
  # The whole network title opens the picker, even when a long title leaves
  # no space for the decorative dropdown arrow in the accessibility tree.
  fixture="$(mktemp "${TMPDIR:-/tmp}/nvpn-network-picker.XXXXXX.xml")"
  trap 'rm -f "$fixture"' EXIT
  for state in on off; do
    cat >"$fixture" <<EOF
<hierarchy><node bounds="[0,0][1080,2410]">
  <node clickable="true" bounds="[0,500][1000,600]"><node text="Unrelated action"/></node>
  <node bounds="[47,198][1033,324]">
    <node clickable="true" bounds="[47,198][896,324]">
      <node text="A network title long enough to hide its dropdown arrow"/>
    </node>
    <node clickable="true" checkable="true" bounds="[896,198][1033,324]">
      <node content-desc="Turn VPN $state"/>
    </node>
  </node>
</node></hierarchy>
EOF
    [[ "$("$ROOT/scripts/mobile-release-join-ui-query.py" \
      "$fixture" network-picker 'Turn VPN ' center)" == '471 261' ]]
    if "$ROOT/scripts/mobile-release-join-ui-query.py" \
      "$fixture" network-picker 'Unrelated toggle' center; then
      echo 'Network picker query accepted an unrelated control' >&2
      exit 1
    fi
  done
)

fixture="$(mktemp "${TMPDIR:-/tmp}/nvpn-release-join-ui.XXXXXX.xml")"
no_viewport_fixture="${fixture%.xml}-no-viewport.xml"
inset_viewport_fixture="${fixture%.xml}-inset-viewport.xml"
pixel_admin_add_fixture="${fixture%.xml}-pixel-admin-add.xml"
trap 'rm -f "$fixture" "$no_viewport_fixture" "$inset_viewport_fixture" "$pixel_admin_add_fixture"' EXIT
printf '%s\n' \
  '<hierarchy>' \
  '  <node bounds="[0,0][1080,2410]" />' \
  '  <node content-desc="Admin Device ID value: npub1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq" bounds="[10,20][110,80]" />' \
  '  <node content-desc="Manual joiner Device ID" bounds="[10,80][110,140]" />' \
  '  <node text="npub1joiner" bounds="[10,80][110,140]" />' \
  '  <node content-desc="Add joining device manually" bounds="[10,140][110,200]" />' \
  '  <node resource-id="fi.siriusbusiness.nvpn:id/roster-participant-pending-a" content-desc="Roster participant pending a" bounds="[0,100][100,200]" />' \
  '  <node resource-id="fi.siriusbusiness.nvpn:id/roster-participant-accepted-b" content-desc="Roster participant accepted b" bounds="[0,200][100,300]" />' \
  '  <node resource-id="manual-join-submit-clipped" bounds="[89,2369][991,2410]" />' \
  '  <node resource-id="manual-join-submit-partial" bounds="[89,1950][991,2200]" />' \
  '  <node resource-id="manual-join-submit-safe" enabled="true" bounds="[89,1800][991,1900]" />' \
  '</hierarchy>' >"$fixture"

description="$(
  "$ROOT/scripts/mobile-release-join-ui-query.py" \
    "$fixture" description-prefix "Admin Device ID value: " description
)"
[[ "$description" == "Admin Device ID value: npub1"* ]]
[[ "$(
  "$ROOT/scripts/mobile-release-join-ui-query.py" \
    "$fixture" resource-prefix roster-participant- count
)" == 2 ]]
if "$ROOT/scripts/mobile-release-join-ui-query.py" \
    "$fixture" resource roster-participant-accepted-a center >/dev/null 2>&1
then
  echo "Pending roster row satisfied an accepted-only UI query" >&2
  exit 1
fi
[[ "$(
  "$ROOT/scripts/mobile-release-join-ui-query.py" \
    "$fixture" resource roster-participant-accepted-b center
)" == "50 250" ]]
[[ "$(
  "$ROOT/scripts/mobile-release-join-ui-query.py" \
    "$fixture" description "Manual joiner Device ID" center
)" == "60 110" ]]
[[ "$(
  "$ROOT/scripts/mobile-release-join-ui-query.py" \
    "$fixture" description "Manual joiner Device ID" width
)" == "100" ]]
[[ "$(
  "$ROOT/scripts/mobile-release-join-ui-query.py" \
    "$fixture" text "npub1joiner" center
)" == "60 110" ]]
if "$ROOT/scripts/mobile-release-join-ui-query.py" \
    "$fixture" resource manual-join-submit-clipped safe-center >/dev/null 2>&1
then
  echo "Clipped Android control was treated as safely tappable" >&2
  exit 1
fi
[[ "$(
  "$ROOT/scripts/mobile-release-join-ui-query.py" \
    "$fixture" resource manual-join-submit-safe safe-center
)" == "540 1850" ]]
[[ "$(
  "$ROOT/scripts/mobile-release-join-ui-query.py" \
    "$fixture" resource manual-join-submit-partial visible-center
)" == "540 2030" ]]
[[ "$(
  "$ROOT/scripts/mobile-release-join-ui-query.py" \
    "$fixture" resource manual-join-submit-safe enabled
)" == true ]]
sed '/bounds="\[0,0\]\[1080,2410\]"/d' \
  "$fixture" >"$no_viewport_fixture"
if "$ROOT/scripts/mobile-release-join-ui-query.py" \
    "$no_viewport_fixture" resource manual-join-submit-safe safe-center \
    >/dev/null 2>&1
then
  echo "Android safe-center accepted a hierarchy without viewport bounds" >&2
  exit 1
fi
printf '%s\n' \
  '<hierarchy>' \
  '  <node bounds="[120,172][1200,2582]">' \
  '    <node resource-id="manual-join-submit-safe" bounds="[209,1972][1111,2072]" />' \
  '    <node resource-id="manual-join-submit-clipped" bounds="[209,2541][1111,2582]" />' \
  '  </node>' \
  '</hierarchy>' >"$inset_viewport_fixture"
[[ "$(
  "$ROOT/scripts/mobile-release-join-ui-query.py" \
    "$inset_viewport_fixture" resource manual-join-submit-safe safe-center
)" == "660 2022" ]]
if "$ROOT/scripts/mobile-release-join-ui-query.py" \
    "$inset_viewport_fixture" resource manual-join-submit-clipped safe-center \
    >/dev/null 2>&1
then
  echo "Inset Android viewport applied its bottom margin from screen zero" >&2
  exit 1
fi
printf '%s\n' \
  '<hierarchy>' \
  '  <node resource-id="android:id/content" bounds="[120,172][960,2347]">' \
  '    <node content-desc="Add joining device manually" enabled="true" bounds="[183,1980][375,2085]" />' \
  '  </node>' \
  '</hierarchy>' >"$pixel_admin_add_fixture"
if "$ROOT/scripts/mobile-release-join-ui-query.py" \
    "$pixel_admin_add_fixture" description "Add joining device manually" \
    safe-center >/dev/null 2>&1
then
  echo "Pixel admin Add control unexpectedly fit the full safe-center margin" >&2
  exit 1
fi
[[ "$(
  "$ROOT/scripts/mobile-release-join-ui-query.py" \
    "$pixel_admin_add_fixture" description "Add joining device manually" \
    visible-center
)" == "279 2013" ]]

# A modal's real scroll viewport must not inherit full-screen navigation margins.
printf '%s\n' \
  '<hierarchy><node resource-id="android:id/content" bounds="[120,863][960,1655]">' \
  '  <node class="android.widget.ScrollView" scrollable="false" bounds="[183,1052][897,1403]">' \
  '    <node content-desc="Join Network" bounds="[183,1251][897,1403]" />' \
  '    <node content-desc="Clipped control" bounds="[183,1300][897,1500]" />' \
  '  </node>' \
  '</node></hierarchy>' >"$inset_viewport_fixture"
[[ "$("$ROOT/scripts/mobile-release-join-ui-query.py" \
  "$inset_viewport_fixture" description 'Join Network' safe-center)" == '540 1327' ]]
if "$ROOT/scripts/mobile-release-join-ui-query.py" \
  "$inset_viewport_fixture" description 'Clipped control' safe-center >/dev/null; then
  echo 'Android modal accepted a control outside its scroll viewport' >&2
  exit 1
fi
[[ "$("$ROOT/scripts/mobile-release-join-ui-query.py" \
  "$inset_viewport_fixture" description 'Clipped control' visible-center)" == '540 1351' ]]

# A partially visible manual-join field must use the clipped safe viewport
# and finish text entry before dismissing the system input method.
(
  # shellcheck disable=SC1091
  source "$ROOT/scripts/lib-mobile-release-join-ui.sh"
  input_events="$(mktemp "${TMPDIR:-/tmp}/nvpn-join-input.XXXXXX")"
  trap 'rm -f "$input_events"' EXIT
  ADB=(fake_adb)
  fake_adb() {
    if [[ "$*" == "shell dumpsys input_method" ]]; then
      printf 'mInputShown=true\n'
    elif [[ "$*" == 'shell input text expected-value' ]]; then
      printf 'text\n' >>"$input_events"
    elif [[ "$*" == 'shell input keyevent KEYCODE_BACK' ]]; then
      printf 'back\n' >>"$input_events"
    fi
  }
  sleep() { :; }
  release_join_android_scroll_to() {
    [[ "$*" == "resource manual-field visible-center" ]]
  }
  release_join_android_tap() { return 1; }
  release_join_android_tap_visible() {
    [[ "$*" == "resource manual-field" ]]
  }
  release_join_android_query() {
    printf 'readback\n' >>"$input_events"
    [[ "$*" == "text expected-value text" ]] \
      && printf 'expected-value\n'
  }

  release_join_android_enter \
    resource manual-field expected-value visible-center
  [[ "$(tr '\n' ' ' <"$input_events")" == 'text readback back ' ]]
)

# Exercise manual admin preparation and submission through observable UI state.
(
  # shellcheck disable=SC1091
  source "$ROOT/scripts/lib-mobile-release-join-ui.sh"
  tmp="$(mktemp -d "${TMPDIR:-/tmp}/nvpn-mobile-admin-add.XXXXXX")"
  trap 'rm -rf "$tmp"' EXIT
  joiner=npub1manualjoiner
  tapped=0
  release_join_android_open_link_device() { :; }
  release_join_android_scroll_to() { :; }
  release_join_android_enter() {
    [[ "$*" == "description Manual joiner Device ID $joiner" ]]
  }
  release_join_android_query() {
    case "$*" in
      "resource-prefix roster-participant- count") printf '2\n' ;;
      "text $joiner center") return 0 ;;
      "description Add joining device manually enabled") printf 'true\n' ;;
      "description Add joining device manually visible-center")
        printf 'point\n' >>"$tmp/events"
        printf '120 240\n'
        ;;
      *) return 1 ;;
    esac
  }
  ADB=(manual_tap_adb)
  manual_tap_adb() {
    [[ "$*" == 'shell input tap 120 240' ]]
    printf 'tap\n' >>"$tmp/events"
    tapped=1
  }
  release_join_android_dump_ui() {
    printf 'unnecessary intermediate snapshot\n' >>"$tmp/events"
  }
  release_join_now_ms() {
    printf 'time\n' >>"$tmp/events"
    printf '1234\n'
  }

  release_join_android_manual_admin_prepare "$joiner" >"$tmp/prepare"
  grep -Fq NVPN_RELEASE_JOIN_ADMIN_ADD_PREPARED=1 "$tmp/prepare"
  [[ "$RELEASE_JOIN_ANDROID_ADMIN_ADD_JOINER" == "$joiner" \
    && "$RELEASE_JOIN_ANDROID_ADMIN_ADD_BEFORE" == 2 ]]
  if release_join_android_manual_admin_tap npub1wrong >/dev/null 2>&1; then
    echo "Android manual admin accepted a different prepared joiner" >&2
    exit 1
  fi
  release_join_android_manual_admin_tap "$joiner" >"$tmp/submit"
  grep -Fq NVPN_RELEASE_JOIN_APPROVAL_SUBMITTED_MS=1234 "$tmp/submit"
  [[ "$tapped" == 1 ]]
  [[ "$(<"$tmp/events")" == $'point\ntime\ntap' ]] || {
    echo "Submission must resolve its target before timing the tap, then let the acceptance observer take the next snapshot" >&2
    exit 1
  }
)

(
  # shellcheck disable=SC1091
  source "$ROOT/scripts/lib-mobile-release-join-ui.sh"
  [[ "$(release_join_desktop_mode full 0)" == 0 ]]
  [[ "$(release_join_desktop_mode full false)" == 0 ]]
  [[ "$(release_join_desktop_mode full 1)" == 1 ]]
  [[ "$(release_join_desktop_mode desktop-only 0)" == 1 ]]
  [[ "$(release_join_desktop_mode manual-only 1)" == 0 ]]
  if release_join_desktop_mode full invalid >/dev/null; then
    echo "invalid desktop join mode was accepted" >&2
    exit 1
  fi
  PRIVATE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/nvpn-join-deadline.XXXXXX")"
  trap 'rm -rf "$PRIVATE_DIR"' EXIT
  quick_poll() { release_join_now_ms; }
  retry_poll() {
    local attempts
    attempts="$(<"$PRIVATE_DIR/retry-attempts.txt")"
    attempts=$((attempts + 1))
    printf '%s\n' "$attempts" >"$PRIVATE_DIR/retry-attempts.txt"
    ((attempts > 1)) || return 1
    release_join_now_ms
  }
  stuck_poll() { sleep 5; }
  late_state_poll() { printf '%s\n' "$((deadline + 1))"; }
  reverse_desktop_poll() { sleep 1; release_join_now_ms; }
  reverse_pixel_poll() { sleep 1.2; release_join_now_ms; }
  timestamp="$PRIVATE_DIR/detected-ms.txt"
  deadline=$(( $(release_join_now_ms) + 500 ))
  release_join_observe_until_ms "$deadline" "$timestamp" quick quick_poll
  [[ -s "$timestamp" ]]
  printf '0\n' >"$PRIVATE_DIR/retry-attempts.txt"
  deadline=$(( $(release_join_now_ms) + 750 ))
  release_join_observe_until_ms \
    "$deadline" "$PRIVATE_DIR/retry.txt" retry retry_poll
  [[ "$(<"$PRIVATE_DIR/retry-attempts.txt")" == 2 ]]
  if release_join_observe_until_ms \
      "$deadline" "$PRIVATE_DIR/late.txt" late-state late_state_poll \
      >/dev/null 2>&1
  then
    echo "late state was accepted after the absolute deadline" >&2
    exit 1
  fi
  before="$(release_join_now_ms)"
  deadline=$((before + 150))
  if release_join_observe_until_ms \
      "$deadline" "$PRIVATE_DIR/unexpected.txt" stuck stuck_poll \
      >/dev/null 2>&1
  then
    echo "blocking state poll unexpectedly met its deadline" >&2
    exit 1
  fi
  elapsed=$(( $(release_join_now_ms) - before ))
  ((elapsed < 1000)) || {
    echo "Blocking public-UI poll outlived its absolute deadline" >&2
    exit 1
  }
  # Keep enough process-start margin for loaded macOS CI while retaining a
  # deadline shorter than the two polls would take if run serially.
  reverse_deadline=$(( $(release_join_now_ms) + 1800 ))
  release_join_observe_pair_until_ms \
    "$reverse_deadline" \
    "$PRIVATE_DIR/reverse-desktop.txt" reverse-desktop \
    reverse_desktop_poll _ \
    "$PRIVATE_DIR/reverse-pixel.txt" reverse-pixel \
    reverse_pixel_poll _
  [[ -s "$PRIVATE_DIR/reverse-desktop.txt" \
    && -s "$PRIVATE_DIR/reverse-pixel.txt" ]]
)

external_fixture="$(mktemp -d "${TMPDIR:-/tmp}/nvpn-external-join-harness.XXXXXX")"
mkdir -p "$external_fixture/source/scripts" "$external_fixture/home"
for file in \
  lib-macos-release-app-ownership.sh \
  macos-release-mobile-join-remote.sh \
  macos_release_join_artifact.py \
  mobile_release_artifact_receipt.py
do
  cp "$ROOT/scripts/$file" "$external_fixture/source/scripts/$file"
done
external_digest="$({
  for file in \
    scripts/lib-macos-release-app-ownership.sh \
    scripts/macos-release-mobile-join-remote.sh \
    scripts/macos_release_join_artifact.py \
    scripts/mobile_release_artifact_receipt.py
  do
    printf '%s\t%s\n' \
      "$file" "$(shasum -a 256 "$external_fixture/source/$file" | awk '{print $1}')"
  done
} | shasum -a 256 | awk '{print $1}')"
external_root="$external_fixture/home/.cache/nvpn-release-mobile-join-harness/$external_digest"
mkdir -p "$(dirname "$external_root")"
mv "$external_fixture/source" "$external_root"
printf '\n' >>"$external_root/scripts/mobile_release_artifact_receipt.py"
if HOME="$external_fixture/home" \
    NVPN_EXTERNAL_HARNESS_DIGEST="$external_digest" \
    "$external_root/scripts/macos-release-mobile-join-remote.sh" unknown \
    >"$external_fixture/tampered.log" 2>&1
then
  echo "tampered transferred macOS harness unexpectedly ran" >&2
  exit 1
fi
grep -Fq 'external harness identity is invalid' "$external_fixture/tampered.log"
rm -rf "$external_root"
mkdir -p "$external_root/scripts"
for file in \
  lib-macos-release-app-ownership.sh \
  macos-release-mobile-join-remote.sh \
  macos_release_join_artifact.py \
  mobile_release_artifact_receipt.py
do
  cp "$ROOT/scripts/$file" "$external_root/scripts/$file"
done
HOME="$external_fixture/home" \
NVPN_APP_REPO_PATH="$ROOT" \
NVPN_MACOS_RELEASE_JOIN_ARTIFACT_DIR="$external_fixture/artifacts" \
NVPN_MACOS_RELEASE_JOIN_PROFILE_STATE_DIR="$external_fixture/profile" \
NVPN_EXTERNAL_HARNESS_DIGEST="$external_digest" \
  "$external_root/scripts/macos-release-mobile-join-remote.sh" cleanup
[[ ! -e "$external_root" ]] || {
  echo "macOS external harness cache survived owned cleanup" >&2
  exit 1
}
rm -rf "$external_fixture"

bash "$ROOT/scripts/test-macos-join-late-observation-harness.sh"
echo "Signed Release public-UI join gate contract passed"

# QR approval must exclude image selection and accessibility lookup from delivery time.
(
  source "$ROOT/scripts/lib-mobile-release-join-ui.sh"
  tmp="$(mktemp -d "${TMPDIR:-/tmp}/nvpn-qr-approval-clock.XXXXXX")"
  trap 'rm -rf "$tmp"' EXIT
  touch "$tmp/request.png"
  printf 'image' >"$tmp/request.png"
  RELEASE_JOIN_ANDROID_SCAN_BEFORE=1
  RELEASE_JOIN_DELIVERY_WAIT_SECS=1
  ADB=(qr_clock_adb)
  qr_clock_adb() {
    if [[ "$*" == 'shell input tap 120 240' ]]; then
      printf 'tap\n' >>"$tmp/events"
    fi
  }
  release_join_android_wait_query() { :; }
  release_join_android_tap() { :; }
  release_join_android_open_devices() { :; }
  release_join_android_wait_through_system_prompts() { :; }
  release_join_require_fresh_ios_pending_qr() { printf 'fresh\n' >>"$tmp/events"; }
  release_join_android_query() {
    case "$*" in
      'description Confirm adding scanned join request center')
        printf 'point\n' >>"$tmp/events"
        [[ "${point_fails:-0}" == 0 ]] || return 1
        printf '120 240\n'
        ;;
      'resource roster-participant-accepted-test-joiner center') : ;;
      'resource-prefix roster-participant- count') printf '2\n' ;;
      *) return 1 ;;
    esac
  }
  release_join_now_ms() {
    printf 'time\n' >>"$tmp/events"
    printf '1234\n'
  }
  release_join_android_scan_submit test-joiner "$tmp/request.png" >"$tmp/submit"
  grep -Fq 'NVPN_RELEASE_JOIN_APPROVAL_SUBMITTED_MS=1234' "$tmp/submit"
  [[ "$(<"$tmp/events")" == $'point\nfresh\ntime\ntap' ]] || {
    echo 'QR delivery timing included setup or lost the fresh pending-QR check' >&2
    exit 1
  }
  : >"$tmp/events"
  point_fails=1
  if release_join_android_scan_submit test-joiner "$tmp/request.png" >"$tmp/failed"; then
    echo 'QR approval accepted a missing confirmation button' >&2
    exit 1
  fi
  [[ "$(<"$tmp/events")" == point ]]
  [[ ! -s "$tmp/failed" ]]
)

(
  source "$ROOT/scripts/lib-mobile-release-join-ui.sh"
  tmp="$(mktemp -d "${TMPDIR:-/tmp}/nvpn-join-carrier-ui.XXXXXX")"
  trap 'rm -rf "$tmp"' EXIT
  python3 - "$tmp/ui.xml" <<'PY'
import sys
import xml.etree.ElementTree as ET
root = ET.Element("hierarchy")
card = ET.SubElement(root, "node", bounds="[0,0][1080,2410]")
labels = [
    ("Connect to non-roster FIPS peers", "false"),
    ("Find peers over Nostr relays", "true"),
    ("Use bootstrap servers", "false"),
    ("Enable WebRTC transport", "false"),
]
for index, (label, checked) in enumerate(labels):
    top = 400 + index * 150
    ET.SubElement(card, "node", checkable="true", checked=checked,
                  bounds=f"[90,{top}][216,{top + 126}]")
    ET.SubElement(card, "node", text=label,
                  bounds=f"[215,{top + 30}][900,{top + 90}]")
ET.SubElement(card, "node", text="Unpaired label", bounds="[215,1100][900,1160]")
ET.ElementTree(root).write(sys.argv[1])
PY
  ADB=(carrier_adb)
  release_join_android_dump_ui() { RELEASE_JOIN_ANDROID_UI_XML="$tmp/ui.xml"; }
  release_join_android_tap_center() { [[ "$1:$2" == 'description:Settings tab' ]]; }
  release_join_android_scroll_to() {
    release_join_android_query "$1" "$2" safe-center >/dev/null
  }
  carrier_adb() {
    [[ "$1:$2:$3" == shell:input:tap ]]
    printf '%s %s\n' "$4" "$5" >>"$tmp/taps"
    [[ "${IGNORE_CARRIER_TAP:-0}" == 0 ]] || return 0
    python3 - "$tmp/ui.xml" "$4" "$5" <<'PY'
import re
import sys
import xml.etree.ElementTree as ET
tree = ET.parse(sys.argv[1])
x, y = map(int, sys.argv[2:])
found = False
for node in tree.iter("node"):
    if node.get("checkable") != "true":
        continue
    left, top, right, bottom = map(int, re.findall(r"\d+", node.get("bounds")))
    if (x, y) == ((left + right) // 2, (top + bottom) // 2):
        node.set("checked", "false" if node.get("checked") == "true" else "true")
        found = True
assert found, "tap did not target a real checkbox"
tree.write(sys.argv[1])
PY
  }
  [[ "$(release_join_android_query checkbox-label 'Unpaired label' count)" == 0 ]]
  release_join_android_normalize_carrier
  [[ "$(wc -l <"$tmp/taps" | tr -d ' ')" == 2 ]]
  [[ "$(release_join_android_query checkbox-label 'Enable WebRTC transport' checked)" == false ]]
  release_join_android_normalize_carrier
  [[ "$(wc -l <"$tmp/taps" | tr -d ' ')" == 2 ]]
  carrier_adb shell input tap 153 463
  IGNORE_CARRIER_TAP=1
  if release_join_android_normalize_carrier; then
    echo 'Android join setup accepted a prerequisite that stayed disabled' >&2
    exit 1
  fi
)
