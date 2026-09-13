#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUNNER="$ROOT/scripts/lib-mobile-ios-release-network.sh"
LOCK_DIR="/tmp/nvpn-ios-release-runner-harness.lock"
lock_acquired=0
for _ in {1..200}; do
  if mkdir "$LOCK_DIR" 2>/dev/null; then
    printf '%s\n' "$$" >"$LOCK_DIR/owner"
    lock_acquired=1
    break
  fi
  lock_owner="$(cat "$LOCK_DIR/owner" 2>/dev/null || true)"
  if [[ "$lock_owner" =~ ^[0-9]+$ ]] \
    && ! kill -0 "$lock_owner" 2>/dev/null
  then
    stale_lock="$LOCK_DIR.stale.$$"
    mv "$LOCK_DIR" "$stale_lock" 2>/dev/null || true
    rm -rf "$stale_lock"
  fi
  sleep 0.05
done
[[ "$lock_acquired" -eq 1 ]] || {
  echo "iOS Release runner harness fixture is already in use" >&2
  exit 1
}
TEMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/nvpn-ios-runner-harness.XXXXXX")"
cleanup() {
  rm -rf "$TEMP_ROOT"
  [[ "$(cat "$LOCK_DIR/owner" 2>/dev/null || true)" != "$$" ]] \
    || rm -rf "$LOCK_DIR"
}
trap cleanup EXIT

fail() {
  echo "iOS Release runner harness failed: $*" >&2
  exit 1
}

# shellcheck disable=SC1090
source "$RUNNER"
# Lock-state command behavior has its own subprocess regression below.
ios_release_network_require_unlocked() { :; }
NVPN_IOS_XCTEST_TERM_GRACE_SECS=1
IOS_BUNDLE_ID=fi.siriusbusiness.nvpn

python3 - \
  "$ROOT/scripts/lib-mobile-android-release-gate.sh" \
  "$ROOT/scripts/lib-mobile-release-join-artifacts.sh" \
  "$RUNNER" <<'PY'
import pathlib
import re
import sys

temporary_file_contracts = (
    (sys.argv[1], "nvpn-installed-release"),
    (sys.argv[2], "nvpn-release-installed"),
)
for source_path, stem in temporary_file_contracts:
    source = pathlib.Path(source_path).read_text(encoding="utf-8")
    match = re.search(rf'mktemp "([^"\n]*{re.escape(stem)}[^"\n]*)"', source)
    if match is None:
        raise SystemExit(f"missing exact temporary-file contract for {stem}")
    if not match.group(1).endswith("XXXXXX"):
        raise SystemExit(f"BSD mktemp template has a suffix after XXXXXX: {stem}")

ios_source = pathlib.Path(sys.argv[3]).read_text(encoding="utf-8")
required_ios_fragments = (
    'mktemp -d "$IOS_RELEASE_NETWORK_SIGNING_DIR/NostrVpnIos-$label.XXXXXX"',
    'IOS_RELEASE_NETWORK_CASE_XCTESTRUN="$IOS_RELEASE_NETWORK_CASE_XCTESTRUN_DIR/NostrVpnIos-$label.xctestrun"',
    'rmdir "$IOS_RELEASE_NETWORK_CASE_XCTESTRUN_DIR"',
    'ios_release_network_require_retained_exact_runner || return 1',
    'build_command+=(clean build-for-testing)',
    'match.group(2).lower(): match.group(1).lower()',
    'identity = identity.lower()',
)
for fragment in required_ios_fragments:
    if fragment not in ios_source:
        raise SystemExit(
            "private XCTest plan does not preserve a real .xctestrun suffix: "
            + fragment
        )
PY

mkdir -p "$TEMP_ROOT/bin"
cat >"$TEMP_ROOT/bin/ios-deploy" <<'USB_FIXTURE'
#!/usr/bin/env python3
import json
import os
import sys
assert sys.argv[1:3] == ["--id", "fixture-device"]
assert "--list_bundle_id" in sys.argv and "--json" in sys.argv
assert "--key=CFBundleIdentifier,CFBundleVersion,CFBundleShortVersionString,ApplicationType,ProfileValidated,SignerIdentity,NVPNBuildGitSha" in sys.argv
with open(os.environ["NVPN_TEST_USB_INVENTORY_LOG"], "a") as log:
    log.write(" ".join(sys.argv[1:]) + "\n")
apps = {}
for bundle, build, version in (
    ("fi.siriusbusiness.nvpn", "4001008", "4.1.5"),
    ("fi.siriusbusiness.nvpn.UITests.xctrunner", "1", os.environ.get("NVPN_TEST_USB_RUNNER_VERSION", "1.0")),
):
    apps[bundle] = {"CFBundleIdentifier": bundle, "CFBundleVersion": build, "CFBundleShortVersionString": version}
print(json.dumps({"Event": "ListBundleId", "Apps": apps}))
USB_FIXTURE
chmod +x "$TEMP_ROOT/bin/ios-deploy"
export PATH="$TEMP_ROOT/bin:$PATH"
export NVPN_TEST_USB_INVENTORY_LOG="$TEMP_ROOT/usb-inventory.log"

cat >"$TEMP_ROOT/bin/ideviceinfo" <<'DEVICE_FIXTURE'
#!/usr/bin/env python3
import os
import plistlib
import sys
assert sys.argv[1] == "-u" and sys.argv[3] == "-x"
sys.stdout.buffer.write(plistlib.dumps({
    "UniqueDeviceID": os.environ.get("NVPN_TEST_USB_DEVICE_ID", sys.argv[2]),
    "DeviceClass": os.environ.get("NVPN_TEST_USB_DEVICE_CLASS", "iPhone"),
    "DeviceName": "Fixture Phone",
}))
DEVICE_FIXTURE
chmod +x "$TEMP_ROOT/bin/ideviceinfo"
(
  device=00000001-0000000000000001
  export NVPN_IOS_EXPECTED_DEVICE_NAME='Fixture Phone'
  [[ "$(ios_release_network_resolve_device "$device")" == "$device" ]]
  resolve_physical_ios_udid() { [[ "$1" == fixture-alias ]]; printf '%s\n' "$device"; }
  [[ "$(ios_release_network_resolve_device fixture-alias)" == "$device" ]]
  for invalid in wrong-device wrong-class wrong-name; do
    unset NVPN_TEST_USB_DEVICE_ID NVPN_TEST_USB_DEVICE_CLASS
    export NVPN_IOS_EXPECTED_DEVICE_NAME='Fixture Phone'
    case "$invalid" in
      wrong-device) export NVPN_TEST_USB_DEVICE_ID=another-device ;;
      wrong-class) export NVPN_TEST_USB_DEVICE_CLASS=Mac ;;
      wrong-name) export NVPN_IOS_EXPECTED_DEVICE_NAME='Another Phone' ;;
    esac
    if ios_release_network_resolve_device "$device" >"$TEMP_ROOT/$invalid.out" 2>/dev/null; then
      fail "USB physical-device readback accepted $invalid"
    fi
    [[ ! -s "$TEMP_ROOT/$invalid.out" ]]
  done
) || fail "USB physical-device selection did not preserve exact identity"

(
  IOS_RELEASE_NETWORK_DERIVED_DATA="$TEMP_ROOT/build-only"
  IOS_RELEASE_NETWORK_DESTINATION=fixture-device
  NVPN_IOS_TEAM_ID=fixture-team
  NVPN_IOS_CODE_SIGN_IDENTITY=fixture-signer
  NVPN_IOS_PROVISIONING_PROFILE_UUID=fixture-app-profile
  NVPN_IOS_PACKET_TUNNEL_PROVISIONING_PROFILE_UUID=fixture-tunnel-profile
  NVPN_BUILD_GIT_SHA=fixture-source
  NVPN_BUILD_TIMESTAMP_UTC=fixture-time
  ios_release_network_xcode_command
  printf '%s\n' "${IOS_RELEASE_NETWORK_XCODE_COMMAND[@]}" >"$TEMP_ROOT/build-command.txt"
  grep -Fxq 'generic/platform=iOS' "$TEMP_ROOT/build-command.txt" \
    && grep -Fxq 'ARCHS=arm64' "$TEMP_ROOT/build-command.txt" \
    && ! grep -Fq fixture-device "$TEMP_ROOT/build-command.txt"
) || fail "compiling the iOS runner still waits for a live physical destination"

runner_root="$TEMP_ROOT/runner-derived/Build/Products/Release-iphoneos/NostrVpnIosUITests-Runner.app"
runner_install_log="$TEMP_ROOT/runner-install.log"
mkdir -p "$runner_root"
plutil -create xml1 "$runner_root/Info.plist"
plutil -insert CFBundleIdentifier \
  -string "$IOS_BUNDLE_ID.UITests.xctrunner" "$runner_root/Info.plist"
(
  IOS_RELEASE_NETWORK_DERIVED_DATA="$TEMP_ROOT/runner-derived"
  IOS_RELEASE_NETWORK_DEVICE=fixture-device
  IOS_RELEASE_NETWORK_DESTINATION=fixture-device
  xcrun() {
    printf '%s\n' "$*" >>"$runner_install_log"
  }
  ios_release_network_install_exact_runner
  ios_release_network_test_command "$TEMP_ROOT/runner-derived/exact.xctestrun"
  ios_release_network_test_command "$TEMP_ROOT/runner-derived/exact.xctestrun"
  [[ " ${IOS_RELEASE_NETWORK_XCODE_COMMAND[*]} " == *" -destination fixture-device "* ]]
) || fail "exact signed iOS runner was not installed in place"
grep -Fxq \
  "devicectl device install app --device fixture-device $runner_root --quiet" \
  "$runner_install_log" \
  || fail "exact signed iOS runner path was not installed before XCTest"
grep -Fq \
  -- '--id fixture-device --list_bundle_id --json' \
  "$NVPN_TEST_USB_INVENTORY_LOG" \
  || fail "installed iOS runner bundle identity was not read back"
if grep -Fq "device uninstall app" "$runner_install_log"; then
  fail "exact iOS runner replacement revoked development trust"
fi
[[ "$(grep -Fxc \
  "devicectl device install app --device fixture-device $runner_root --quiet" \
  "$runner_install_log")" -eq 1 ]] \
  || fail "exact iOS runner was replaced between XCTest cases"
runner_command="$({
  sed -n '/ios_release_network_test_command()/,/^}/p' "$RUNNER"
})"
if grep -Fq 'ios_release_network_install_exact_runner' <<<"$runner_command"; then
  fail "per-case XCTest command still replaces the retained exact runner"
fi

reuse_app="$TEMP_ROOT/reuse/Nostr VPN.app"
reuse_runner="$TEMP_ROOT/reuse/NostrVpnIosUITests-Runner.app"
reuse_receipt="$TEMP_ROOT/reuse/app-receipt.json"
reuse_runner_receipt="$TEMP_ROOT/reuse/installed-runner-receipt.json"
reuse_inventory_log="$TEMP_ROOT/reuse/inventory.log"
mkdir -p "$reuse_app" "$reuse_runner"
python3 - "$reuse_app/Info.plist" "$reuse_runner/Info.plist" \
  "$reuse_receipt" <<'PY'
import json
import plistlib
import sys

app, runner, receipt = sys.argv[1:]
for path, identifier, build, version in (
    (app, "fi.siriusbusiness.nvpn", "4001008", "4.1.5"),
    (runner, "fi.siriusbusiness.nvpn.UITests.xctrunner", "1", "1.0"),
):
    with open(path, "wb") as handle:
        plistlib.dump({
            "CFBundleIdentifier": identifier,
            "CFBundleVersion": build,
            "CFBundleShortVersionString": version,
        }, handle)
with open(receipt, "w", encoding="utf-8") as handle:
    json.dump({
        "installedBuildNumber": "4001008",
        "installedMarketingVersion": "4.1.5",
    }, handle)
PY
reuse_runner_tree="$(
  python3 "$ROOT/scripts/mobile_release_artifact_receipt.py" tree-sha "$reuse_runner"
)"
reuse_device_sha="$(printf %s fixture-device | shasum -a 256 | awk '{print $1}')"
python3 - \
  "$reuse_runner_receipt" "$reuse_runner_tree" "$reuse_device_sha" <<'PY'
import json, sys
json.dump({
    "receiptSchema": 1,
    "artifactType": "installed iOS XCTest runner",
    "bundleIdentifier": "fi.siriusbusiness.nvpn.UITests.xctrunner",
    "runnerBundleTreeSha256": sys.argv[2],
    "selectedPhysicalDeviceIdentifierSha256": sys.argv[3],
    "xctestrunSha256": "d" * 64,
    "testProductsTreeSha256": "e" * 64,
}, open(sys.argv[1], "w"))
PY

run_installed_reuse_readback() (
  local runner_version="$1"
  IOS_RELEASE_NETWORK_SIGNING_DIR="$TEMP_ROOT/reuse"
  IOS_RELEASE_NETWORK_DEVICE=fixture-device
  export NVPN_TEST_USB_RUNNER_VERSION="$runner_version"
  export NVPN_TEST_USB_INVENTORY_LOG="$reuse_inventory_log"
  ios_release_network_require_installed_reuse \
    "$reuse_app" "$reuse_runner" "$reuse_receipt" \
    "$reuse_runner_receipt" "$reuse_runner_tree" "$reuse_device_sha" \
    "$(printf 'd%.0s' {1..64})" "$(printf 'e%.0s' {1..64})"
)

run_installed_reuse_readback 1.0 \
  || fail "exact installed iOS app and runner readback was rejected"
if run_installed_reuse_readback 2.0 \
    >"$TEMP_ROOT/reuse-mismatch.log" 2>&1
then
  fail "installed iOS runner version mismatch was accepted"
fi
grep -Fq 'Installed iOS app/runner identity differs' \
  "$TEMP_ROOT/reuse-mismatch.log" \
  || fail "installed iOS runner mismatch did not fail closed"
cp "$reuse_runner_receipt" "$reuse_runner_receipt.clean"
python3 - "$reuse_runner_receipt" <<'PY'
import json, pathlib, sys
path = pathlib.Path(sys.argv[1])
value = json.loads(path.read_text())
value["selectedPhysicalDeviceIdentifierSha256"] = "0" * 64
path.write_text(json.dumps(value))
PY
if run_installed_reuse_readback 1.0 \
    >"$TEMP_ROOT/reuse-device-mismatch.log" 2>&1
then
  fail "installed iOS runner receipt accepted another phone"
fi
grep -Fq 'installed iOS runner receipt mismatch' \
  "$TEMP_ROOT/reuse-device-mismatch.log" \
  || fail "installed iOS runner device mismatch did not fail closed"
mv "$reuse_runner_receipt.clean" "$reuse_runner_receipt"
cp "$reuse_runner_receipt" "$reuse_runner_receipt.clean"
python3 - "$reuse_runner_receipt" <<'PY'
import json, pathlib, sys
path = pathlib.Path(sys.argv[1])
value = json.loads(path.read_text())
value["runnerBundleTreeSha256"] = "0" * 64
path.write_text(json.dumps(value))
PY
if run_installed_reuse_readback 1.0 \
    >"$TEMP_ROOT/reuse-runner-tree-mismatch.log" 2>&1
then
  fail "installed iOS runner receipt accepted another runner binary"
fi
grep -Fq 'installed iOS runner receipt mismatch' \
  "$TEMP_ROOT/reuse-runner-tree-mismatch.log" \
  || fail "installed iOS runner digest mismatch did not fail closed"
mv "$reuse_runner_receipt.clean" "$reuse_runner_receipt"
if grep -Eq 'device (install|uninstall) app' "$reuse_inventory_log"; then
  fail "installed-artifact validation changed an iOS installation"
fi

python3 - "$RUNNER" <<'PY'
import pathlib
import sys

source = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
reuse = source.split("ios_release_network_prepare_reuse() {", 1)[1].split(
    "\nios_release_network_prepare() {", 1
)[0]
if 'NVPN_MOBILE_WG_EXIT_INSTALL_IOS:-1' not in source:
    raise SystemExit("exact installed iOS reuse lacks an explicit install mode")
for required in (
    'ios_release_network_require_installed_reuse',
    'IOS_RELEASE_NETWORK_EXACT_RUNNER_READY=1',
    'testProductsTreeSha256',
):
    if required not in reuse:
        raise SystemExit(f"exact installed iOS reuse omits {required}")
disabled = reuse.split(
    '\n    0)', 1
)[1].split(';;', 1)[0]
if "device install app" in disabled or "device uninstall app" in disabled:
    raise SystemExit("disabled iOS install mode changes the installation")
PY

NVPN_MOBILE_WG_EXIT_INSTALL_IOS=0
NVPN_MOBILE_WG_EXIT_REUSE_IOS_BUILD=0
bool_is_true() { return 1; }
if ios_release_network_prepare fixture-device \
    >"$TEMP_ROOT/reuse-required.log" 2>&1
then
  fail "disabled iOS install mode ran without exact artifact reuse"
fi
grep -Fq 'requires exact artifact reuse' "$TEMP_ROOT/reuse-required.log" \
  || fail "disabled iOS install mode did not fail closed"
unset NVPN_MOBILE_WG_EXIT_INSTALL_IOS NVPN_MOBILE_WG_EXIT_REUSE_IOS_BUILD

for stem in nvpn-installed-release nvpn-release-installed NostrVpnIos-case.xctestrun; do
  first="$(mktemp "$TEMP_ROOT/$stem.XXXXXX")"
  second="$(mktemp "$TEMP_ROOT/$stem.XXXXXX")"
  [[ "$first" != "$second" && -f "$first" && -f "$second" ]] \
    || fail "two consecutive BSD-style mktemp calls collided for $stem"
  rm -f "$first" "$second"
done

run_bounded() {
  local name="$1" timeout="$2" launch_timeout="$3" marker="$4"
  shift 4
  ios_release_network_run_bounded_xcode \
    "$name" "$timeout" "$launch_timeout" "$marker" "" \
    "$TEMP_ROOT/$name.log" "$TEMP_ROOT/$name-markers.tsv" "" "" \
    "$@"
}

run_bounded success 5 2 FIRST \
  bash -c 'printf "FIRST\nordinary output\n"'
grep -Fxq FIRST "$TEMP_ROOT/success.log" \
  || fail "bounded runner did not retain command output"

set +e
authorization_started=$SECONDS
run_bounded authorization 10 8 FIRST \
  bash -c 'echo "Error Domain=com.apple.dt.XCTest.XCTFuture Code=1000 \"Timed out while enabling automation mode.\""; sleep 30' \
  >"$TEMP_ROOT/authorization-diagnostic.log" 2>&1
authorization_status=$?
set -e
[[ "$authorization_status" -eq 125 ]] \
  || fail "pre-method Apple authorization failure did not fail closed"
((SECONDS - authorization_started < 5)) \
  || fail "bounded runner waited after Apple had already denied automation"
grep -Fq 'Apple UI Automation authorization timed out before any test method' \
  "$TEMP_ROOT/authorization-diagnostic.log" \
  || fail "pre-method Apple authorization failure was hidden by a generic launch error"
grep -Fq 'Enter the automation PIN on the selected iPhone when prompted' \
  "$TEMP_ROOT/authorization-diagnostic.log" \
  || fail "Apple authorization diagnostic omitted the required on-device action"

# The runner emits identical markers to stderr and its Documents file. Use the
# captured stream after a successful test; file vending can hang independently.
stream_log="$TEMP_ROOT/streamed-markers.log"
stream_markers="$TEMP_ROOT/collected-markers.log"
printf 'ordinary XCTest output\r\nNVPN_XCUITEST_RUN_ID=stream-run\r\nNVPN_XCUITEST_STARTED=1\r\nNVPN_XCUITEST_RUN_ID=stream-run\r\nNVPN_IOS_RELEASE_DISCONNECT_PASSED=1\r\n' >"$stream_log"
(
  xcrun() { fail "streamed marker collection contacted the phone"; }
  ios_release_network_collect_markers "$stream_log" stream-run "$stream_markers"
) || fail "could not collect exact-run streamed markers"
[[ "$(wc -l <"$stream_markers" | tr -d '[:space:]')" -eq 4 ]] \
  || fail "streamed marker collection lost or invented markers"
grep -Fxq NVPN_IOS_RELEASE_DISCONNECT_PASSED=1 "$stream_markers" \
  || fail "streamed markers retained carriage returns"

for invalid_stream in stale mixed missing-start missing-context duplicate-start; do
  case "$invalid_stream" in
    stale) printf '%s\n' NVPN_XCUITEST_RUN_ID=stale NVPN_XCUITEST_STARTED=1 ;;
    mixed) printf '%s\n' NVPN_XCUITEST_RUN_ID=stream-run NVPN_XCUITEST_STARTED=1 NVPN_XCUITEST_RUN_ID=stale NVPN_IOS_RELEASE_DISCONNECT_PASSED=1 ;;
    missing-start) printf '%s\n' NVPN_XCUITEST_RUN_ID=stream-run NVPN_IOS_RELEASE_DISCONNECT_PASSED=1 ;;
    missing-context) printf '%s\n' NVPN_XCUITEST_STARTED=1 ;;
    duplicate-start) printf '%s\n' NVPN_XCUITEST_RUN_ID=stream-run NVPN_XCUITEST_STARTED=1 NVPN_XCUITEST_RUN_ID=stream-run NVPN_XCUITEST_STARTED=1 ;;
  esac >"$stream_log"
  if ios_release_network_collect_markers "$stream_log" stream-run "$stream_markers"; then
    fail "accepted $invalid_stream streamed evidence"
  fi
  [[ ! -e "$stream_markers" ]] || fail "failed marker collection retained partial evidence"
done

device_marker="$TEMP_ROOT/device-marker.log"
printf '%s\n' \
  'NVPN_XCUITEST_RUN_ID=device-marker' \
  'NVPN_XCUITEST_STARTED=1' >"$device_marker"
(
  xcrun() { fail "launch marker observation contacted the phone"; }
  ios_release_network_stop_forced_xctrunner() {
    fail "device marker success unexpectedly cleared the XCTest runner"
  }
  ios_release_network_run_bounded_xcode \
    device-marker 5 2 NVPN_XCUITEST_STARTED=1 device-marker \
    "$TEMP_ROOT/device-marker.log.output" \
    "$TEMP_ROOT/device-marker-host-markers.tsv" \
    fixture-device "" \
    bash -c 'printf "Running tests...\n"; cat "$1"; sleep 2' _ "$device_marker"
)
grep -Fq 'Running tests...' "$TEMP_ROOT/device-marker.log.output" \
  || fail "device-marker fixture did not retain runner launch output"
grep -Fxq NVPN_XCUITEST_STARTED=1 "$TEMP_ROOT/device-marker.log.output" \
  || fail "device-marker fixture lost the first streamed marker"

cat >"$TEMP_ROOT/bin/idevicesyslog" <<'PROCESS_FIXTURE'
#!/usr/bin/env bash
[[ "$*" == '-u fixture-device pidlist' ]] || exit 2
[[ "${NVPN_TEST_RUNNER_INVENTORY_FAIL:-0}" != 1 ]] || exit 1
printf '1 launchd\n2 SpringBoard\n4242 NostrVpnIosUITests-Runner\n4343 OtherUITests-Runner\n'
PROCESS_FIXTURE
chmod +x "$TEMP_ROOT/bin/idevicesyslog"
[[ "$(ios_release_network_xctrunner_process_ids fixture-device)" == 4242 ]] \
  || fail "runner process query was not scoped to the exact XCTest runner"
if NVPN_TEST_RUNNER_INVENTORY_FAIL=1 ios_release_network_xctrunner_process_ids fixture-device; then
  fail "failed USB process inventory unexpectedly passed"
fi

scoped_cleanup_log="$TEMP_ROOT/scoped-cleanup.log"
stale_device_marker="$TEMP_ROOT/stale-device-marker.log"
runner_process_probe_count="$TEMP_ROOT/runner-process-probe-count"
printf '%s\n' \
  'NVPN_XCUITEST_RUN_ID=stale-run' \
  'NVPN_XCUITEST_STARTED=1' >"$stale_device_marker"
set +e
(
  ios_release_network_xctrunner_installed() {
    printf '%s\n' installation-probe >>"$scoped_cleanup_log"
    return 0
  }
  ios_release_network_xctrunner_process_ids() {
    local count=0
    [[ ! -f "$runner_process_probe_count" ]] \
      || count="$(wc -l <"$runner_process_probe_count" | tr -d '[:space:]')"
    printf '%s\n' process-probe >>"$runner_process_probe_count"
    [[ "$count" -eq 0 ]] && printf '%s\n' 4242
    return 0
  }
  xcrun() {
    printf 'xcrun %s\n' "$*" >>"$scoped_cleanup_log"
  }
  ios_release_network_run_bounded_xcode \
    device-no-marker 5 1 NVPN_XCUITEST_STARTED=1 device-no-marker \
    "$TEMP_ROOT/device-no-marker.log" \
    "$TEMP_ROOT/device-no-marker-host-markers.tsv" \
    fixture-device "" \
    bash -c 'cat "$1"; sleep 10' _ "$stale_device_marker"
)
device_no_marker_status=$?
set -e
[[ "$device_no_marker_status" -eq 125 ]] \
  || fail "device no-marker timeout returned $device_no_marker_status instead of 125"
grep -Fxq \
  'xcrun devicectl device process terminate --device fixture-device --pid 4242 --timeout 5 --quiet' \
  "$scoped_cleanup_log" \
  || fail "forced launch timeout did not terminate only the nVPN XCTest runner process"
if grep -Fq 'device uninstall app' "$scoped_cleanup_log"; then
  fail "forced launch timeout uninstalled the retained nVPN XCTest runner"
fi
[[ "$(grep -Fxc installation-probe "$scoped_cleanup_log")" -eq 2 ]] \
  || fail "forced launch timeout did not verify the runner remained installed"
[[ "$(wc -l <"$runner_process_probe_count" | tr -d '[:space:]')" -eq 2 ]] \
  || fail "forced launch timeout did not verify the runner process stopped"
[[ "$(grep -c '^xcrun ' "$scoped_cleanup_log")" -eq 1 ]] \
  || fail "forced launch timeout performed broad or repeated device cleanup"

set +e
run_bounded missing-marker 5 2 NEVER \
  bash -c 'printf "ordinary failure\n"; exit 7'
missing_status=$?
run_bounded launch-timeout 5 1 FIRST \
  bash -c 'sleep 10'
launch_status=$?
run_bounded total-timeout 1 5 FIRST \
  bash -c 'trap "" TERM; printf "FIRST\n"; (trap "" TERM; sleep 10) & wait'
total_status=$?
set -e
[[ "$missing_status" -eq 125 ]] \
  || fail "missing first marker returned $missing_status instead of 125"
[[ "$launch_status" -eq 125 ]] \
  || fail "launch timeout returned $launch_status instead of 125"
[[ "$total_status" -eq 124 ]] \
  || fail "total timeout returned $total_status instead of 124"
if ps -axo command= | grep -F 'sleep 10' | grep -v grep >/dev/null; then
  fail "bounded runner left its fixture child running"
fi

spec="$(
  python3 - <<'PY'
import base64
import json

payload = {
    "wireGuardConfig": (
        "[Interface]\n"
        "PrivateKey = fake-private-key-material\n"
        "[Peer]\n"
        "pReShArEdKeY = fake-preshared-key-material\n"
    )
}
print(base64.b64encode(json.dumps(payload).encode()).decode())
PY
)"
private_log="$TEMP_ROOT/private.log"
private_result="$TEMP_ROOT/private.xcresult"
private_summary="$TEMP_ROOT/private-xcresult-summary.json"
private_redaction="$TEMP_ROOT/private-diagnostic-redaction.json"
printf '%s\nfake-private-key-material\n' "$spec" >"$private_log"
mkdir -p "$private_result/Data"
printf '%s\n' "$spec" >"$private_result/Data/private"
IOS_RELEASE_NETWORK_CASE_XCTESTRUN="$TEMP_ROOT/private.xctestrun"
printf '%s\n' "$spec" >"$IOS_RELEASE_NETWORK_CASE_XCTESTRUN"
ios_release_network_delete_private_test_products
[[ ! -e "$TEMP_ROOT/private.xctestrun" ]] \
  || fail "private xctestrun survived cleanup"
[[ -e "$private_log" && -d "$private_result" ]] \
  || fail "evidence was deleted with the private xctestrun"
ios_release_network_preserve_diagnostics \
  "$spec" "$private_log" "$private_result"
[[ ! -e "$private_result" ]] \
  || fail "unsafe xcresult was retained instead of redacted to its summary"
grep -Fq '<redacted-private-gate-input>' "$private_log" \
  || fail "private xcode log was not redacted"
python3 - "$private_redaction" <<'PY'
import json
import sys

payload = json.load(open(sys.argv[1], encoding="utf-8"))
if payload.get("logRedacted") is not True:
    raise SystemExit("redaction receipt did not record log redaction")
if payload.get("xcresultRedactedToSummary") is not True:
    raise SystemExit("redaction receipt did not record xcresult redaction")
if payload.get("retainedFullXcresult") is not False:
    raise SystemExit("redaction receipt claims unsafe xcresult retention")
PY
ios_release_network_assert_retained_no_secrets \
  "$spec" "$private_log" "$private_summary" "$private_redaction"

isolated_psk="$TEMP_ROOT/isolated-preshared-key.log"
printf '%s\n' 'fake-preshared-key-material' >"$isolated_psk"
if ios_release_network_assert_retained_no_secrets \
    "$spec" "$isolated_psk" 2>/dev/null
then
  fail "isolated WireGuard PresharedKey survived the retained-artifact scan"
fi
[[ "$(ios_release_network_private_data redact "$spec" "$isolated_psk")" == true ]] \
  || fail "isolated WireGuard PresharedKey was not redacted"
grep -Fq '<redacted-private-gate-input>' "$isolated_psk" \
  || fail "isolated WireGuard PresharedKey redaction was not persisted"
ios_release_network_assert_retained_no_secrets "$spec" "$isolated_psk"

visual_result="$TEMP_ROOT/visual-only.xcresult"
visual_log="$TEMP_ROOT/visual-only.log"
visual_redaction="$TEMP_ROOT/visual-only-diagnostic-redaction.json"
printf '%s\n' 'ordinary xcode output' >"$visual_log"
mkdir -p "$visual_result/Data"
printf '%s\n' 'rendered screenshot bytes without searchable input text' \
  >"$visual_result/Data/screenshot"
ios_release_network_preserve_diagnostics \
  "$spec" "$visual_log" "$visual_result"
[[ ! -e "$visual_result" ]] \
  || fail "WireGuard UI xcresult was retained despite visual secret exposure"
python3 - "$visual_redaction" <<'PY'
import json
import sys

payload = json.load(open(sys.argv[1], encoding="utf-8"))
if payload.get("privateVisualInputForcedSummaryOnly") is not True:
    raise SystemExit("redaction receipt omitted the visual-input policy")
if payload.get("retainedFullXcresult") is not False:
    raise SystemExit("redaction receipt claims WireGuard UI xcresult retention")
PY

pending_log="$TEMP_ROOT/interrupted.log"
pending_result="$TEMP_ROOT/interrupted.xcresult"
printf '%s\n' "$spec" >"$pending_log"
mkdir -p "$pending_result"
printf '%s\n' "$spec" >"$pending_result/private"
ios_release_network_register_diagnostics \
  "$spec" "$pending_log" "$pending_result"
ios_release_network_abort_active_run
[[ ! -e "$pending_log" && ! -e "$pending_result" ]] \
  || fail "interrupt cleanup retained unredacted diagnostics"

cleanup_started=$SECONDS
bash -c '
  set -euo pipefail
  ROOT="$1"
  source "$ROOT/scripts/lib-mobile-ios-release-network.sh"
  source "$ROOT/scripts/lib-mobile-wireguard-fixture.sh"
  NVPN_MOBILE_WG_EXIT_IOS_UI_RESULT_DIR="$2/exit-cleanup"
  IOS_RELEASE_NETWORK_PREPARED=1
  NVPN_IOS_DISCONNECT_CLEANUP_TOTAL_TIMEOUT_SECS=5
  NVPN_IOS_XCTEST_TERM_GRACE_SECS=1
  ios_release_network_disconnect_cleanup_inner() { return 0; }
  trap "mobile_wg_fixture_begin_cleanup; ios_release_network_disconnect_cleanup" EXIT
' _ "$ROOT" "$TEMP_ROOT"
((SECONDS - cleanup_started < 3)) \
  || fail "completed EXIT cleanup waited for its watchdog deadline"

(
  # Finish cleanup while the real watchdog is sleeping. Its shell must reap
  # that child before returning, rather than leaving it to the outer supervisor.
  IOS_RELEASE_NETWORK_PREPARED=1
  NVPN_MOBILE_WG_EXIT_IOS_UI_RESULT_DIR="$TEMP_ROOT/watchdog-reap"
  NVPN_IOS_DISCONNECT_CLEANUP_TOTAL_TIMEOUT_SECS=5
  watchdog_sleep_pid_file="$TEMP_ROOT/watchdog-sleep.pid"
  sleep() {
    if [[ "$1" == 0.1 ]]; then
      command sleep 1 &
      printf '%s\n' "$!" >"$watchdog_sleep_pid_file"
      wait "$!"
    else
      command sleep "$@"
    fi
  }
  ios_release_network_disconnect_cleanup_inner() {
    while [[ ! -s "$watchdog_sleep_pid_file" ]]; do command sleep 0.01; done
  }
  ios_release_network_disconnect_cleanup
  watchdog_sleep_pid="$(cat "$watchdog_sleep_pid_file")"
  if kill -0 "$watchdog_sleep_pid" 2>/dev/null; then
    kill "$watchdog_sleep_pid" 2>/dev/null || true
    fail "completed iOS cleanup orphaned its watchdog sleep"
  fi
)

timeout_signing="$(
  mktemp -d "$TEMP_ROOT/nvpn-ios-release-signing.XXXXXX"
)"
IOS_RELEASE_NETWORK_PREPARED=1
IOS_RELEASE_NETWORK_SIGNING_DIR="$timeout_signing"
IOS_RELEASE_NETWORK_ACTIVE_PGID_FILE="$timeout_signing/active-xcode.pgid"
IOS_RELEASE_NETWORK_CLEANUP_SPEC_BASE64=""
NVPN_MOBILE_WG_EXIT_IOS_UI_RESULT_DIR="$TEMP_ROOT/timeout-artifacts"
NVPN_IOS_DISCONNECT_CLEANUP_TOTAL_TIMEOUT_SECS=1
timeout_child_pid_file="$TEMP_ROOT/disconnect-cleanup-child.pid"
ios_release_network_disconnect_cleanup_inner() {
  trap "" TERM
  (trap "" TERM; sleep 10) &
  printf '%s\n' "$!" >"$timeout_child_pid_file"
  wait
}
set +e
ios_release_network_disconnect_cleanup
cleanup_status=$?
set -e
[[ "$cleanup_status" -ne 0 ]] \
  || fail "end-to-end disconnect cleanup deadline passed a hung cleanup"
[[ ! -e "$timeout_signing" ]] \
  || fail "timed-out disconnect cleanup retained private signing state"
timeout_child_pid="$(<"$timeout_child_pid_file")"
if ps -o stat= -p "$timeout_child_pid" 2>/dev/null \
    | grep -Eqv '^[[:space:]]*Z'; then
  fail "disconnect cleanup deadline left its fixture child running"
fi

for token in \
  'IOS_RELEASE_NETWORK_DESTINATION="platform=iOS,id=$device_udid,arch=arm64"' \
  '-parallel-testing-enabled NO' \
  'appSigningClass": "distribution"' \
  'runnerSigningClass": "development"' \
  'ios_release_network_write_runner_diagnostics' \
  'ios_release_network_preserve_diagnostics' \
  'ios_release_network_validate_disconnect_markers' \
  'NVPN_XCUITEST_RUN_ID=$runner_run_id' \
  'NVPN_IOS_XCTEST_LAUNCH_TIMEOUT_SECS' \
  'NVPN_IOS_XCTEST_CLEANUP_TIMEOUT_SECS' \
  'NVPN_IOS_DISCONNECT_CLEANUP_TOTAL_TIMEOUT_SECS'
do
  grep -Fq -- "$token" "$RUNNER" \
    || fail "runner contract lacks: $token"
done
grep -Fq 'NVPN_IOS_XCTEST_CLEANUP_TIMEOUT_SECS:-330' "$RUNNER" \
  || fail "disconnect cleanup does not cover Apple's five-minute authorization lifetime"
grep -Fq 'NVPN_IOS_DISCONNECT_CLEANUP_TOTAL_TIMEOUT_SECS:-$((cleanup_timeout + 30))' "$RUNNER" \
  || fail "disconnect cleanup wrapper can expire before its scoped XCTest runner"

disconnect="$TEMP_ROOT/disconnect-markers.log"
printf '%s\n' \
  'NVPN_IOS_RELEASE_DIRECT_CLEANUP_PASSED=1' \
  'NVPN_IOS_RELEASE_DISCONNECT_PASSED=1' >"$disconnect"
ios_release_network_validate_disconnect_markers "$disconnect" ""
if ios_release_network_validate_disconnect_markers \
    "$disconnect" "$spec" 2>/dev/null
then
  fail "underlay cleanup accepted no Wi-Fi restoration marker"
fi
printf '%s\n' \
  'NVPN_IOS_RELEASE_DIRECT_CLEANUP_PASSED=1' \
  'NVPN_IOS_RELEASE_DISCONNECT_PASSED=1' \
  'NVPN_IOS_RELEASE_HOME_WIFI_RESTORED=1' >"$disconnect"
ios_release_network_validate_disconnect_markers "$disconnect" "$spec"
if ios_release_network_validate_disconnect_markers \
    "$disconnect" "" 2>/dev/null
then
  fail "non-underlay cleanup accepted a Wi-Fi restoration marker"
fi
printf '%s\n' \
  'NVPN_IOS_RELEASE_DIRECT_CLEANUP_PASSED=1' \
  'NVPN_IOS_RELEASE_DISCONNECT_PASSED=1' \
  'NVPN_IOS_RELEASE_HOME_WIFI_ENABLED_NO_SAVED_SSID=1' >"$disconnect"
ios_release_network_validate_disconnect_markers "$disconnect" "$spec"
printf '%s\n' \
  'NVPN_IOS_RELEASE_DIRECT_CLEANUP_PASSED=1' \
  'NVPN_IOS_RELEASE_DISCONNECT_PASSED=1' \
  'NVPN_IOS_RELEASE_HOME_WIFI_RESTORED=1' \
  'NVPN_IOS_RELEASE_HOME_WIFI_ENABLED_NO_SAVED_SSID=1' >"$disconnect"
if ios_release_network_validate_disconnect_markers \
    "$disconnect" "$spec" 2>/dev/null
then
  fail "disconnect cleanup accepted conflicting Wi-Fi restoration markers"
fi
python3 "$ROOT/scripts/test-ios-packet-tunnel-processes.py"   || fail "disconnect process inventory regression failed"
python3 "$ROOT/scripts/test-mobile-ios-artifact-readback.py" \
  || fail "installed artifact USB identity regression failed"
if sed -n '/ios_release_network_test_command()/,/^}/p' "$RUNNER" \
  | grep -Fq -- '-quiet'
then
  fail "physical xcodebuild runner still hides exact launch diagnostics"
fi
diagnostics="$(
  sed -n \
    '/ios_release_network_write_runner_diagnostics()/,/^}/p' "$RUNNER"
)"
grep -Fq '"testBundleHostedByDebuggableRunner": true' <<<"$diagnostics" \
  || fail "iOS runner receipt does not describe the hosted test bundle"
if grep -Eq 'test_entitlements|"testBundleDebuggable": true' <<<"$diagnostics"; then
  fail "nested iOS test bundle still requires a debug entitlement"
fi

echo "MOBILE_IOS_RELEASE_RUNNER_HARNESS_OK"

bash "$ROOT/scripts/test-mobile-ios-unattended-harness.sh"
