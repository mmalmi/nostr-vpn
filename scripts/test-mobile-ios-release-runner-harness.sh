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
)
for fragment in required_ios_fragments:
    if fragment not in ios_source:
        raise SystemExit(
            "private XCTest plan does not preserve a real .xctestrun suffix: "
            + fragment
        )
PY

runner_root="$TEMP_ROOT/runner-derived/Build/Products/Release-iphoneos/NostrVpnIosUITests-Runner.app"
runner_install_log="$TEMP_ROOT/runner-install.log"
mkdir -p "$runner_root"
plutil -create xml1 "$runner_root/Info.plist"
plutil -insert CFBundleIdentifier \
  -string "$IOS_BUNDLE_ID.UITests.xctrunner" "$runner_root/Info.plist"
(
  IOS_RELEASE_NETWORK_DERIVED_DATA="$TEMP_ROOT/runner-derived"
  IOS_RELEASE_NETWORK_DEVICE=fixture-device
  xcrun() {
    printf '%s\n' "$*" >>"$runner_install_log"
    if [[ "$*" == "devicectl device info apps"* ]]; then
      printf '%s\n' "$IOS_BUNDLE_ID.UITests.xctrunner"
    fi
  }
  ios_release_network_install_exact_runner
  ios_release_network_test_command "$TEMP_ROOT/runner-derived/exact.xctestrun"
  ios_release_network_test_command "$TEMP_ROOT/runner-derived/exact.xctestrun"
) || fail "exact signed iOS runner was not installed in place"
grep -Fxq \
  "devicectl device install app --device fixture-device $runner_root --quiet" \
  "$runner_install_log" \
  || fail "exact signed iOS runner path was not installed before XCTest"
grep -Fq \
  "device info apps --device fixture-device --bundle-id $IOS_BUNDLE_ID.UITests.xctrunner" \
  "$runner_install_log" \
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
  xcrun() {
    local bundle="" output="" previous=""
    printf '%s\n' "$*" >>"$reuse_inventory_log"
    for argument in "$@"; do
      case "$previous" in
        --bundle-id) bundle="$argument" ;;
        --json-output) output="$argument" ;;
      esac
      previous="$argument"
    done
    [[ -n "$bundle" && -n "$output" ]] || return 1
    python3 - "$output" "$bundle" "$runner_version" <<'PY'
import json
import sys

path, bundle, runner_version = sys.argv[1:]
is_runner = bundle.endswith(".UITests.xctrunner")
with open(path, "w", encoding="utf-8") as handle:
    json.dump({
        "info": {"outcome": "success"},
        "result": {
            "deviceIdentifier": "fixture-coredevice-uuid-not-hardware-udid",
            "apps": [{
                "bundleIdentifier": bundle,
                "bundleVersion": "1" if is_runner else "4001008",
                "version": runner_version if is_runner else "4.1.5",
            }],
        },
    }, handle)
PY
  }
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
if "--use-destination-artifacts" not in source:
    raise SystemExit("retained iOS reuse lost destination-artifact XCTest")
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

device_marker="$TEMP_ROOT/device-marker.log"
printf '%s\n' \
  'NVPN_XCUITEST_RUN_ID=device-marker' \
  'NVPN_XCUITEST_STARTED=1' >"$device_marker"
(
  ios_release_network_copy_runner_markers() {
    cp "$device_marker" "$2"
  }
  ios_release_network_stop_forced_xctrunner() {
    fail "device marker success unexpectedly cleared the XCTest runner"
  }
  ios_release_network_run_bounded_xcode \
    device-marker 5 1 NVPN_XCUITEST_STARTED=1 device-marker \
    "$TEMP_ROOT/device-marker.log.output" \
    "$TEMP_ROOT/device-marker-host-markers.tsv" \
    fixture-device "" \
    bash -c 'printf "Running tests...\n"; sleep 2'
)
grep -Fq 'Running tests...' "$TEMP_ROOT/device-marker.log.output" \
  || fail "device-marker fixture did not retain runner launch output"
if grep -Fq NVPN_XCUITEST_STARTED=1 "$TEMP_ROOT/device-marker.log.output"; then
  fail "device-marker fixture accidentally streamed the first marker"
fi

process_fixture='{
  "result": {
    "runningProcesses": [
      {
        "executable": "file:///private/NostrVpnIosUITests-Runner.app/NostrVpnIosUITests-Runner",
        "processIdentifier": 4242
      },
      {
        "executable": "file:///private/OtherUITests-Runner.app/OtherUITests-Runner",
        "processIdentifier": 4343
      }
    ]
  }
}'
xcrun_json_output_path() {
  local previous="" argument output=""
  for argument in "$@"; do
    [[ "$previous" != --json-output ]] || output="$argument"
    previous="$argument"
  done
  [[ -n "$output" && "$output" != /dev/stdout ]] || return 2
  printf '%s\n' "$output"
}
process_json_path="$TEMP_ROOT/process-json-path"
(
  xcrun() {
    local output
    output="$(xcrun_json_output_path "$@")" || return
    printf '%s\n' "$output" >"$process_json_path"
    printf '%s\n' "$process_fixture" >"$output"
  }
  [[ "$(ios_release_network_xctrunner_process_ids fixture-device)" == 4242 ]]
) || fail "runner process query was not scoped to the exact XCTest runner"
queried_process_json="$(<"$process_json_path")"
[[ ! -e "$queried_process_json" ]] \
  || fail "runner process query retained its private JSON output"

failed_process_json_path="$TEMP_ROOT/failed-process-json-path"
set +e
(
  xcrun() {
    local output
    output="$(xcrun_json_output_path "$@")" || return
    printf '%s\n' "$output" >"$failed_process_json_path"
    return 1
  }
  ios_release_network_xctrunner_process_ids fixture-device
)
failed_process_status=$?
set -e
[[ "$failed_process_status" -ne 0 ]] \
  || fail "failed device process query unexpectedly passed"
failed_process_json="$(<"$failed_process_json_path")"
[[ ! -e "$failed_process_json" ]] \
  || fail "failed runner process query retained its private JSON output"

scoped_cleanup_log="$TEMP_ROOT/scoped-cleanup.log"
stale_device_marker="$TEMP_ROOT/stale-device-marker.log"
runner_process_probe_count="$TEMP_ROOT/runner-process-probe-count"
printf '%s\n' \
  'NVPN_XCUITEST_RUN_ID=stale-run' \
  'NVPN_XCUITEST_STARTED=1' >"$stale_device_marker"
set +e
(
  ios_release_network_copy_runner_markers() {
    cp "$stale_device_marker" "$2"
  }
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
    bash -c 'sleep 10'
)
device_no_marker_status=$?
set -e
[[ "$device_no_marker_status" -eq 125 ]] \
  || fail "device no-marker timeout returned $device_no_marker_status instead of 125"
grep -Fxq \
  'xcrun devicectl device process terminate --device fixture-device --pid 4242 --quiet' \
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
packet_processes="$TEMP_ROOT/packet-processes.json"
(
  xcrun() {
    local previous="" output="" argument
    for argument in "$@"; do
      [[ "$previous" != --json-output ]] || output="$argument"
      previous="$argument"
    done
    printf '%s\n' '{"result":{"runningProcesses":[]}}' >"$output"
  }
  ios_release_network_require_packet_tunnel_stopped \
    fixture-device "$packet_processes" 1
) || fail "disconnect cleanup rejected an absent PacketTunnel"
(
  xcrun() {
    local previous="" output="" argument
    for argument in "$@"; do
      [[ "$previous" != --json-output ]] || output="$argument"
      previous="$argument"
    done
    printf '%s\n' \
      '{"result":{"runningProcesses":[{"executable":"file:///Nostr%20VPN.app/PlugIns/Nostr%20VPN%20Tunnel.appex/Nostr%20VPN%20Tunnel","processIdentifier":7}]}}' \
      >"$output"
  }
  ! ios_release_network_require_packet_tunnel_stopped \
    fixture-device "$packet_processes" 1 >/dev/null 2>&1
) || fail "disconnect cleanup accepted a live PacketTunnel"
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
