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
)
for file in "${FILES[@]}"; do
  bash -n "$file"
done
grep -Fq 'NVPN_RELEASE_JOIN_IOS_SETUP_WAIT_SECS:-90' \
  "$ROOT/scripts/mobile-release-join-e2e.sh"
grep -Fq 'RELEASE_JOIN_IOS_SETUP_WAIT_SECS <= 90' \
  "$ROOT/scripts/mobile-release-join-e2e.sh"
grep -Fq 'NVPN_RELEASE_JOIN_IOS_SETUP_WAIT_SECS:-90' \
  "$ROOT/scripts/macos-vm-release-mobile-join-e2e.sh"
grep -Fq 'RELEASE_JOIN_IOS_SETUP_WAIT_SECS <= 90' \
  "$ROOT/scripts/macos-vm-release-mobile-join-e2e.sh"
join_ui="$ROOT/scripts/lib-mobile-release-join-ui.sh"

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
  xcrun() {
    [[ "$*" == *"device copy from"* ]]
    [[ "$*" == *"--domain-identifier fi.siriusbusiness.nvpn.UITests.xctrunner"* ]]
    [[ "$*" == *"--source Documents/nvpn-release-join-qr-ABC123.png"* ]]
    local argument destination="" previous=""
    for argument in "$@"; do
      [[ "$previous" != --destination ]] || destination="$argument"
      previous="$argument"
    done
    [[ -n "$destination" ]]
    cp "$captured" "$destination"
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
  xcrun() {
    local argument bundle="" previous=""
    printf '%s\n' "$*" >>"$private/xcrun.log"
    [[ "$*" == *"device copy to"* ]]
    for argument in "$@"; do
      [[ "$previous" != --domain-identifier ]] || bundle="$argument"
      previous="$argument"
    done
    [[ -n "$bundle" && "$*" == *"--source $image"* ]]
  }
  release_join_stage_ios_qr_image "$image" fixture.png
  [[ "$(grep -c 'device copy to' "$private/xcrun.log")" == 2 ]]
  grep -Fq -- '--domain-identifier fi.siriusbusiness.nvpn ' "$private/xcrun.log"
  grep -Fq -- \
    '--domain-identifier fi.siriusbusiness.nvpn.UITests.xctrunner ' \
    "$private/xcrun.log"
)
python3 -B "$ROOT/scripts/macos_release_join_artifact.py" --help >/dev/null

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
  # Android no-install reuse pulls and byte-compares the real installed APK.
  # shellcheck disable=SC1091
  source "$ROOT/scripts/lib-mobile-release-join-artifacts.sh"
  tmp="$(mktemp -d "${TMPDIR:-/tmp}/nvpn-join-android-noinstall.XXXXXX")"
  trap 'rm -rf "$tmp"' EXIT
  apk="$tmp/app-release.apk"
  printf 'exact installed apk\n' >"$apk"
  fake_adb() {
    printf '%s\n' "$*" >>"$tmp/adb.log"
    case "$*" in
      "shell pm path fi.siriusbusiness.nvpn")
        printf 'package:/data/app/exact/base.apk\n'
        ;;
      "shell pm list packages") printf 'package:fi.siriusbusiness.nvpn\n' ;;
      "pull /data/app/exact/base.apk "*) cp "$apk" "$3" ;;
      "shell dumpsys package fi.siriusbusiness.nvpn") printf '  flags=[ HAS_CODE ]\n' ;;
      "shell pidof fi.siriusbusiness.nvpn") printf '1234\n' ;;
      "install -r "*) return 99 ;;
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
  NVPN_RELEASE_JOIN_INSTALL_ANDROID=0
  NVPN_RELEASE_JOIN_INSTALL_IOS=1
  release_join_configure_install_modes
  release_join_assert_fips_unchanged() { :; }
  release_join_assert_app_unchanged() { :; }
  release_join_prepare_android_release
  if grep -Fq 'install -r' "$tmp/adb.log"; then
    echo "Android exact-artifact reuse unexpectedly installed an APK" >&2
    exit 1
  fi
  python3 - "$RESULT_DIR/android-release-install.json" <<'PY'
import json, sys
r = json.load(open(sys.argv[1], encoding="utf-8"))
assert r["installedArtifactVerified"] is True
assert r["replacementInstall"] is False
assert r["replacementInstallVerified"] is False
PY
)

(
  # Real devicectl inventory shape uses a CoreDevice UUID unrelated to the UDID.
  # shellcheck disable=SC1091
  source "$ROOT/scripts/lib-mobile-release-join-artifacts.sh"
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
  xcrun() {
    printf '%s\n' "$*" >>"$tmp/devicectl.log"
    [[ "$*" != *"device install app"* ]] || return 99
    local output="" previous=""
    for argument in "$@"; do
      [[ "$previous" != --json-output ]] || output="$argument"
      previous="$argument"
    done
    [[ -n "$output" ]] || return 0
    python3 - "$output" "${FAKE_IOS_RUNNER_VERSION:-1.0}" <<'PY'
import json, sys
json.dump({"info": {"outcome": "success"}, "result": {
    "deviceIdentifier": "coredevice-uuid-not-hardware-udid", "apps": [
        {"bundleIdentifier": "example.unrelated", "bundleVersion": "9", "version": "9"},
        {"bundleIdentifier": "fi.siriusbusiness.nvpn", "bundleVersion": "4001008", "version": "4.1.5"},
        {"bundleIdentifier": "fi.siriusbusiness.nvpn.UITests.xctrunner", "bundleVersion": "1", "version": sys.argv[2]},
    ]}}, open(sys.argv[1], "w"))
PY
  }
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
)

(
  # shellcheck disable=SC1091
  source "$ROOT/scripts/lib-mobile-release-join-ui.sh"
  # shellcheck disable=SC1091
  source "$ROOT/scripts/lib-mobile-ios-release-network.sh"
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
  # shellcheck disable=SC1091
  source "$ROOT/scripts/lib-mobile-release-join-ui.sh"
  # shellcheck disable=SC1091
  source "$ROOT/scripts/lib-mobile-ios-release-network.sh"
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
  # shellcheck disable=SC1091
  source "$ROOT/scripts/lib-mobile-release-join-ui.sh"
  # shellcheck disable=SC1091
  source "$ROOT/scripts/lib-mobile-ios-release-network.sh"
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
  release_join_now_ms() { printf '1000\n'; }
  assert_delivery_deadline() {
    [[ "$1" =~ ^[0-9]+$ && "$2" =~ ^[0-9]+$ ]]
    trace "delivered:$3"
  }
  release_join_valid_npub() { [[ "$1" == npub1* ]]; }
  release_join_restart_ios_in_place() { trace restart-ios; }
  release_join_reset_android_state() { trace reset-android; }
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
  release_join_ios_wait_marker() {
    trace "ios-marker:$1"
  }
  release_join_ios_finish_test() { trace "ios-finish:$active_test"; }
  ios_marker_value_from() {
    case "$2" in
      NVPN_RELEASE_JOIN_JOINER_ID) printf '%s\n' npub1iosjoiner ;;
      NVPN_RELEASE_JOIN_ROSTER_APPLIED_MS) printf '1000\n' ;;
      NVPN_RELEASE_JOIN_QR_RELAUNCH_DURABLE) printf '%s\n' "$RELEASE_JOIN_ANDROID_ADMIN_ID" ;;
      NVPN_RELEASE_JOIN_QR_CONTENT_WIDTH_BPS) printf '9900\n' ;;
      NVPN_RELEASE_JOIN_ADMIN_RELAUNCH_DURABLE) printf '%s\n' "$RELEASE_JOIN_ANDROID_JOINER_ID" ;;
      NVPN_RELEASE_JOIN_RELAUNCH_DURABLE) printf '%s\n' "$RELEASE_JOIN_ANDROID_ADMIN_ID" ;;
      *) return 1 ;;
    esac
  }
  release_join_android_assert_pending_qr() { trace android-qr-pending; }
  release_join_android_wait_qr_join_complete() { trace "android-qr-accepted:$1"; }
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
  release_join_android_wait_join_complete() { trace "android-manual-accepted:$1"; }
  release_join_android_manual_admin_prepare() { trace "android-admin-prepared:$1"; }
  release_join_android_manual_admin_tap() {
    trace "android-admin-submitted:$1"
    echo 'NVPN_RELEASE_JOIN_MARKER NVPN_RELEASE_JOIN_APPROVAL_SUBMITTED_MS=1000'
  }

  : >"$trace_file"
  phase_ios_admin_android_qr
  grep -Fxq ios-admin "$trace_file"
  grep -Fxq android-background-foreground "$trace_file"
  grep -Fxq stage-ios-qr "$trace_file"
  grep -Fxq 'android-qr-accepted:npub1iosadmin' "$trace_file"
  grep -Fxq 'android-relaunch-accepted:npub1iosadmin' "$trace_file"

  : >"$trace_file"
  phase_android_admin_ios_qr
  grep -Fxq android-admin "$trace_file"
  grep -Fxq android-scan-ready "$trace_file"
  grep -Fxq 'android-scan-accepted:npub1iosjoiner' "$trace_file"
  grep -Fxq 'ios-finish:testShowPhysicalJoinQrAndRequireRosterCompletion' "$trace_file"
  [[ "$RELEASE_JOIN_IOS_QR_RELAUNCH_DURABLE" == 1 \
    && "$RELEASE_JOIN_IOS_QR_CONTENT_WIDTH_BPS" == 9900 ]]

  : >"$trace_file"
  phase_ios_admin_android_manual
  grep -Fxq android-manual-joiner "$trace_file"
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
    if [[ "$kind" == resource && "$expected" == join-request-qr-content ]]; then
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
  RELEASE_JOIN_DELIVERY_WAIT_SECS=2
  RELEASE_JOIN_ANDROID_JOINER_ID=npub1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq
  snapshot=0

  release_join_android_launch() { :; }
  release_join_android_dump_ui() {
    snapshot=$((snapshot + 1))
  }
  release_join_android_query_dumped() {
    local kind="$1" expected="$2" output="$3"
    if ((snapshot == 1)); then
      if [[ "$kind" == description && "$expected" == "Join request QR code" ]]; then
        return 0
      fi
      if [[ "$kind" == resource \
        && "$expected" == joiner-device-id-value \
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

# A partially visible manual-join field must use the clipped safe viewport
# rather than silently failing before text entry.
(
  # shellcheck disable=SC1091
  source "$ROOT/scripts/lib-mobile-release-join-ui.sh"
  ADB=(fake_adb)
  fake_adb() {
    if [[ "$*" == "shell dumpsys input_method" ]]; then
      printf 'mInputShown=true\n'
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
    [[ "$*" == "text expected-value text" ]] \
      && printf 'expected-value\n'
  }

  release_join_android_enter \
    resource manual-field expected-value visible-center
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
      *) return 1 ;;
    esac
  }
  release_join_android_tap_visible() {
    [[ "$*" == "description Add joining device manually" ]]
    tapped=1
  }
  release_join_android_dump_ui() { :; }
  release_join_android_query_dumped() {
    if [[ "$*" == "description Add joining device manually center" ]]; then
      ((tapped == 0))
      return
    fi
    [[ "$*" == "resource roster-participant-pending-$joiner center" \
      && "$tapped" == 1 ]]
  }
  release_join_now_ms() { printf '1234\n'; }

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

echo "Signed Release public-UI join gate contract passed"
