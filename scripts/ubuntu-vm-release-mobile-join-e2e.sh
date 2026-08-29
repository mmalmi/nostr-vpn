#!/usr/bin/env bash
# Real imported Linux Release GTK app <-> physical Pixel manual join, both roles.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "$ROOT/scripts/release_common.sh"
# shellcheck disable=SC1091
source "$ROOT/scripts/mobile_env.sh"
# shellcheck disable=SC1091
source "$ROOT/scripts/lib-mobile-release-join-artifacts.sh"
# shellcheck disable=SC1091
source "$ROOT/scripts/lib-mobile-release-artifact-reuse.sh"
# shellcheck disable=SC1091
source "$ROOT/scripts/lib-mobile-release-join-ui.sh"

load_release_env "$ROOT"
load_env_file_defaults "${NVPN_ZAPSTORE_ENV_FILE:-$ROOT/.env.zapstore.local}"
load_mobile_env "$ROOT"
release_join_configure_install_modes

SSH_HOST="${NVPN_UBUNTU_SSH_HOST:-${1:-}}"
GUEST_SRC_ROOT="${NVPN_UBUNTU_GUEST_SRC_ROOT:-src}"
GUEST_REPO="$GUEST_SRC_ROOT/nostr-vpn-release-gate"
[[ -n "$SSH_HOST" ]] || {
  echo "Set NVPN_UBUNTU_SSH_HOST for Linux Release desktop/mobile join" >&2
  exit 2
}
[[ "$(uname -s)" == Darwin ]] || {
  echo "Linux Release desktop/mobile join must be controlled by the host Mac" >&2
  exit 2
}

RESULT_PARENT="${NVPN_RELEASE_JOIN_RESULT_DIR:-$ROOT/artifacts/mobile-release-join}"
RESULT_DIR="${NVPN_LINUX_RELEASE_MOBILE_JOIN_RESULT_DIR:-$RESULT_PARENT/linux}"
PRIVATE_DIR="$RESULT_DIR/.private-$$"
PHASE_EVIDENCE="$RESULT_DIR/phase-evidence.json"
SUMMARY="$RESULT_DIR/summary.json"
REMOTE_SCRIPT="./scripts/linux-release-mobile-join-remote.sh"
RELEASE_JOIN_UI_WAIT_SECS="${NVPN_RELEASE_JOIN_UI_WAIT_SECS:-15}"
RELEASE_JOIN_DELIVERY_WAIT_SECS="${NVPN_RELEASE_JOIN_DELIVERY_WAIT_SECS:-15}"
mkdir -p "$RESULT_DIR" "$PRIVATE_DIR"
chmod 700 "$PRIVATE_DIR"

[[ "$RELEASE_JOIN_UI_WAIT_SECS" =~ ^[1-9][0-9]*$ \
  && "$RELEASE_JOIN_DELIVERY_WAIT_SECS" =~ ^[1-9][0-9]*$ ]] || {
  echo "Linux desktop/mobile join timeouts must be positive integers" >&2
  exit 2
}
((RELEASE_JOIN_DELIVERY_WAIT_SECS <= 15)) || {
  echo "Linux desktop/mobile join completion deadline cannot exceed 15 seconds" >&2
  exit 2
}

APP_GIT_SHA="$(git -C "$ROOT" rev-parse HEAD)"
APP_GIT_TREE="$(git -C "$ROOT" rev-parse 'HEAD^{tree}')"
[[ -z "$(git -C "$ROOT" status --porcelain --untracked-files=all)" ]] || {
  echo "Linux desktop/mobile join requires a clean committed candidate" >&2
  exit 2
}
[[ "${NVPN_EXPECTED_APP_GIT_SHA:-}" =~ ^[0-9a-f]{40}$ \
  && "$APP_GIT_SHA" == "$NVPN_EXPECTED_APP_GIT_SHA" ]] || {
  echo "Set NVPN_EXPECTED_APP_GIT_SHA to the exact committed candidate" >&2
  exit 2
}
if [[ -n "${NVPN_EXPECTED_APP_GIT_TREE:-}" \
  && "$APP_GIT_TREE" != "$NVPN_EXPECTED_APP_GIT_TREE" ]]
then
  echo "Linux desktop/mobile join candidate tree differs from the pin" >&2
  exit 2
fi

ANDROID_REQUESTED="${NVPN_ANDROID_SERIAL:-${ANDROID_SERIAL:-}}"
[[ -n "$ANDROID_REQUESTED" ]] || {
  echo "Set NVPN_ANDROID_SERIAL to the exact physical Pixel" >&2
  exit 2
}
[[ -n "${NVPN_EXPECTED_ANDROID_DEVICE_MODEL:-}" ]] || {
  echo "Set NVPN_EXPECTED_ANDROID_DEVICE_MODEL to the exact physical Pixel model" >&2
  exit 2
}
ANDROID_SERIAL_SELECTED="$(
  select_physical_android_serial "${ADB_BIN:-adb}" "$ANDROID_REQUESTED"
)"
ADB=("${ADB_BIN:-adb}" -s "$ANDROID_SERIAL_SELECTED")
ANDROID_MODEL="$("${ADB[@]}" shell getprop ro.product.model | tr -d '\r')"
[[ "$ANDROID_MODEL" == "$NVPN_EXPECTED_ANDROID_DEVICE_MODEL" ]] || {
  echo "Selected Android model differs from NVPN_EXPECTED_ANDROID_DEVICE_MODEL" >&2
  exit 2
}
export RESULT_DIR PRIVATE_DIR RELEASE_JOIN_UI_WAIT_SECS
export RELEASE_JOIN_DELIVERY_WAIT_SECS

release_join_require_clean_fips
release_join_assert_app_unchanged "$APP_GIT_SHA" "$APP_GIT_TREE"

# shellcheck disable=SC1091
source "$ROOT/scripts/lib-ubuntu-vm-imported-release.sh"
export NVPN_UBUNTU_IMPORT_EVIDENCE_DIR="$RESULT_DIR/import"

remote_pid=""
acceptance_observer_pids=()
import_ready=0
service_cleanup_armed=0

remote() {
  local mode="$1"
  shift
  local remote_command argument
  ubuntu_vm_import_ssh_command
  printf -v remote_command \
    'cd %q && %q %q %q %q %q %q %q' \
    "$GUEST_REPO" \
    "$REMOTE_SCRIPT" \
    "$mode" \
    "$NVPN_UBUNTU_IMPORTED_DIR/mobile-join" \
    "$NVPN_UBUNTU_IMPORTED_APP" \
    "$NVPN_UBUNTU_IMPORTED_CLI" \
    "$NVPN_UBUNTU_IMPORTED_RECEIPT" \
    "$NVPN_UBUNTU_IMPORTED_PACKAGE_RECEIPT"
  for argument in "$@"; do
    printf -v remote_command '%s %q' "$remote_command" "$argument"
  done
  "${NVPN_UBUNTU_IMPORT_SSH[@]}" "$remote_command"
}

cleanup() {
  local status="$?"
  trap - EXIT
  local observer_pid
  for observer_pid in "${acceptance_observer_pids[@]-}"; do
    kill "$observer_pid" >/dev/null 2>&1 || true
    wait "$observer_pid" >/dev/null 2>&1 || true
  done
  if [[ -n "$remote_pid" ]] && kill -0 "$remote_pid" 2>/dev/null; then
    remote Stop >/dev/null 2>&1 || true
    wait "$remote_pid" >/dev/null 2>&1 || true
  fi
  if [[ "$import_ready" -eq 1 ]]; then
    remote ReadDaemonLog >"$RESULT_DIR/daemon.log" 2>/dev/null || true
    remote Cleanup "$service_cleanup_armed" >/dev/null 2>&1 || status=1
  fi
  if [[ "${RELEASE_JOIN_DEVICE_MUTATED:-0}" -eq 1 ]]; then
    "${ADB[@]}" shell rm -f /sdcard/nvpn-release-join.xml \
      >/dev/null 2>&1 || true
  fi
  if ! ubuntu_vm_cleanup_imported_release_bundle; then
    status=1
  fi
  if [[ "$status" -ne 0 && -s "$PRIVATE_DIR/android-ui.xml" ]]; then
    cp "$PRIVATE_DIR/android-ui.xml" "$RESULT_DIR/android-ui-failure.xml"
  fi
  rm -rf "$PRIVATE_DIR"
  exit "$status"
}
trap cleanup EXIT

case "${NVPN_UBUNTU_SKIP_GIT_SYNC:-0}" in
  1|true|TRUE|True|yes|YES|Yes|on|ON|On) ;;
  *) "$ROOT/scripts/ubuntu-vm-git-sync.sh" "$SSH_HOST" ;;
esac
ubuntu_vm_import_release_bundle
import_ready=1
# Import validation sources the product checkout's artifact helpers. Restore
# the caller's explicit install policy before any device mutation.
release_join_configure_install_modes
remote ReadReceipt >"$RESULT_DIR/import/remote-bundle-receipt.json"
cmp -s \
  "$RESULT_DIR/import/host-bundle-receipt.json" \
  "$RESULT_DIR/import/remote-bundle-receipt.json" || {
  echo "Ubuntu VM receipt differs from the exact host-built bundle receipt" >&2
  exit 1
}
IMPORTED_DESKTOP_APP_SHA="$(
  jq -er '.appGitSha' "$RESULT_DIR/import/host-bundle-receipt.json"
)"
IMPORTED_DESKTOP_APP_TREE="$(
  jq -er '.appGitTree' "$RESULT_DIR/import/host-bundle-receipt.json"
)"

if release_join_reuse_artifacts; then
  release_join_validate_android_reuse
  RELEASE_JOIN_ARTIFACTS_VALIDATED=1
  export RELEASE_JOIN_ARTIFACTS_VALIDATED
fi
RELEASE_JOIN_DEVICE_MUTATION_ALLOWED=1
export RELEASE_JOIN_DEVICE_MUTATION_ALLOWED
release_join_prepare_android_release

python3 - "$RESULT_DIR/selected-physical-android.json" "$ANDROID_MODEL" <<'PY'
import json
import os
import pathlib
import sys
import tempfile

path = pathlib.Path(sys.argv[1])
path.parent.mkdir(parents=True, exist_ok=True)
descriptor, temporary_name = tempfile.mkstemp(
    prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
)
temporary = pathlib.Path(temporary_name)
try:
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        json.dump(
            {
                "physicalDeviceRequired": True,
                "model": sys.argv[2],
                "expectedModelMatched": True,
            },
            handle,
            indent=2,
            sort_keys=True,
        )
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)
finally:
    temporary.unlink(missing_ok=True)
PY

marker_value() {
  python3 - "$1" "$2" <<'PY'
import json
import sys

value = json.load(open(sys.argv[1], encoding="utf-8"))
result = value.get(sys.argv[2])
if result is None or isinstance(result, (dict, list)):
    raise SystemExit(1)
if isinstance(result, bool):
    print(str(result).lower())
else:
    print(result)
PY
}

wait_remote_field() {
  local output="$1" field="$2" expected="${3:-__present__}"
  local timeout="${4:-$RELEASE_JOIN_DELIVERY_WAIT_SECS}"
  local deadline=$((SECONDS + timeout))
  local temporary="$output.tmp"
  while ((SECONDS < deadline)); do
    if remote ReadMarker >"$temporary" 2>/dev/null \
      && python3 - "$temporary" "$field" "$expected" <<'PY'
import json
import sys

value = json.load(open(sys.argv[1], encoding="utf-8"))
field, expected = sys.argv[2:]
if field not in value:
    raise SystemExit(1)
actual = value[field]
if expected == "__present__":
    if actual is None or actual == "":
        raise SystemExit(1)
elif expected in ("true", "false"):
    if actual is not (expected == "true"):
        raise SystemExit(1)
elif str(actual) != expected:
    raise SystemExit(1)
PY
    then
      mv "$temporary" "$output"
      return 0
    fi
    if [[ -n "$remote_pid" ]] && ! kill -0 "$remote_pid" 2>/dev/null; then
      local remote_status=0
      wait "$remote_pid" || remote_status=$?
      remote_pid=""
      if remote ReadMarker >"$temporary" 2>/dev/null \
        && python3 - "$temporary" "$field" "$expected" <<'PY'
import json
import sys

value = json.load(open(sys.argv[1], encoding="utf-8"))
field, expected = sys.argv[2:]
if field not in value:
    raise SystemExit(1)
actual = value[field]
if expected == "__present__":
    if actual is None or actual == "":
        raise SystemExit(1)
elif expected in ("true", "false"):
    if actual is not (expected == "true"):
        raise SystemExit(1)
elif str(actual) != expected:
    raise SystemExit(1)
PY
      then
        mv "$temporary" "$output"
        return "$remote_status"
      fi
      [[ -s "$temporary" ]] && cat "$temporary" >&2
      return 1
    fi
    sleep 0.2
  done
  rm -f "$temporary"
  return 1
}

finish_remote() {
  local log="$1" status=0
  wait "$remote_pid" || status=$?
  remote_pid=""
  if [[ "$status" -ne 0 ]]; then
    tail -n 160 "$log" >&2 || true
  fi
  return "$status"
}

REMOTE_CLOCK_OFFSET_MS=0
REMOTE_CLOCK_UNCERTAINTY_MS=0

calibrate_remote_clock() {
  local best_rtt=999999 best_offset=0 before after guest rtt offset
  for _ in 1 2 3; do
    before="$(release_join_now_ms)"
    guest="$(remote NowMs)"
    after="$(release_join_now_ms)"
    [[ "$guest" =~ ^[0-9]+$ ]] || {
      echo "Ubuntu VM clock did not report epoch milliseconds" >&2
      return 1
    }
    rtt=$((after - before))
    offset=$((((before + after) / 2) - guest))
    if ((rtt < best_rtt)); then
      best_rtt="$rtt"
      best_offset="$offset"
    fi
  done
  REMOTE_CLOCK_OFFSET_MS="$best_offset"
  REMOTE_CLOCK_UNCERTAINTY_MS=$(((best_rtt + 1) / 2 + 250))
  ((REMOTE_CLOCK_UNCERTAINTY_MS <= 2000)) || {
    echo "Ubuntu VM clock calibration uncertainty is too high" >&2
    return 1
  }
  python3 - \
    "$RESULT_DIR/clock-calibration.json" \
    "$REMOTE_CLOCK_OFFSET_MS" \
    "$REMOTE_CLOCK_UNCERTAINTY_MS" <<'PY'
import json
import os
import pathlib
import sys
import tempfile

path = pathlib.Path(sys.argv[1])
descriptor, temporary_name = tempfile.mkstemp(
    prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
)
temporary = pathlib.Path(temporary_name)
try:
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        json.dump(
        {
            "guestToHostOffsetMilliseconds": int(sys.argv[2]),
            "uncertaintyMilliseconds": int(sys.argv[3]),
        },
            handle,
            indent=2,
            sort_keys=True,
        )
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)
finally:
    temporary.unlink(missing_ok=True)
PY
}

delivery_from_guest_submit() {
  local submitted_guest="$1" completed_host="$2" label="$3"
  local submitted_host elapsed
  [[ "$submitted_guest" =~ ^[0-9]+$ ]] || {
    echo "$label lacks the real GTK approval timestamp" >&2
    return 1
  }
  submitted_host=$((submitted_guest + REMOTE_CLOCK_OFFSET_MS))
  elapsed=$((completed_host - submitted_host + REMOTE_CLOCK_UNCERTAINTY_MS))
  ((elapsed >= 0 && elapsed <= RELEASE_JOIN_DELIVERY_WAIT_SECS * 1000)) || {
    echo "$label took conservatively ${elapsed}ms after GTK approval" >&2
    return 1
  }
  printf '%s\n' "$elapsed"
}

delivery_from_host_submit() {
  local submitted="$1" completed="$2" label="$3" elapsed
  [[ "$submitted" =~ ^[0-9]+$ ]] || {
    echo "$label lacks the real Pixel approval timestamp" >&2
    return 1
  }
  elapsed=$((completed - submitted))
  ((elapsed >= 0 && elapsed <= RELEASE_JOIN_DELIVERY_WAIT_SECS * 1000)) || {
    echo "$label took ${elapsed}ms after Pixel approval" >&2
    return 1
  }
  printf '%s\n' "$elapsed"
}

linux_admin_desktop_visible() {
  local output="$1" temporary="$1.tmp" accepted_guest
  remote ReadMarker >"$temporary" 2>/dev/null \
    && [[ "$(marker_value "$temporary" desktopAccepted)" == true ]] \
    && accepted_guest="$(marker_value "$temporary" acceptedAtMs)" \
    && [[ "$accepted_guest" =~ ^[0-9]+$ ]] \
    && mv "$temporary" "$output" \
    && printf '%s\n' "$((accepted_guest + REMOTE_CLOCK_OFFSET_MS))"
}

linux_admin_pixel_visible() {
  release_join_android_accepted_snapshot_ms "$1"
}

calibrate_remote_clock

# Imported Linux desktop admin -> physical Pixel joiner.
release_join_reset_android_state
remote Reset >"$RESULT_DIR/desktop-admin-reset.log"
remote Bootstrap >"$RESULT_DIR/desktop-admin-bootstrap.log"
remote ReadMarker >"$RESULT_DIR/desktop-admin-bootstrap.json"
remote CreateAdmin "Release Linux admin" >"$RESULT_DIR/desktop-create-admin.log"
remote ReadMarker >"$RESULT_DIR/desktop-create-admin.json"
DESKTOP_ADMIN_NPUB="$(
  marker_value "$RESULT_DIR/desktop-create-admin.json" adminNpub
)"
DESKTOP_NETWORK_ID="$(
  marker_value "$RESULT_DIR/desktop-create-admin.json" networkId
)"
release_join_valid_npub "$DESKTOP_ADMIN_NPUB"
[[ -n "$DESKTOP_NETWORK_ID" ]]
service_cleanup_armed=1
remote InstallService >"$RESULT_DIR/desktop-admin-service.log"
release_join_android_manual_submit "$DESKTOP_ADMIN_NPUB" "$DESKTOP_NETWORK_ID" \
  >"$RESULT_DIR/pixel-manual-submit.log" 2>&1
release_join_android_wait_vpn_connected

desktop_add_log="$RESULT_DIR/desktop-admin-add-pixel.log"
remote AdminAdd "$RELEASE_JOIN_ANDROID_JOINER_ID" "Release Pixel" \
  >"$desktop_add_log" 2>&1 &
remote_pid=$!
wait_remote_field \
  "$RESULT_DIR/desktop-admin-add-submitted.json" \
  approvalSubmittedMs __present__ 10 || {
  tail -n 160 "$desktop_add_log" >&2 || true
  exit 1
}
DESKTOP_SUBMITTED_GUEST="$(
  marker_value "$RESULT_DIR/desktop-admin-add-submitted.json" \
    approvalSubmittedMs
)"
DESKTOP_ADMIN_DEADLINE_HOST_MS=$((
  DESKTOP_SUBMITTED_GUEST + REMOTE_CLOCK_OFFSET_MS \
    + RELEASE_JOIN_DELIVERY_WAIT_SECS * 1000
))
desktop_detected_file="$RESULT_DIR/desktop-admin-desktop-detected-ms.txt"
pixel_detected_file="$RESULT_DIR/desktop-admin-pixel-detected-ms.txt"
rm -f "$desktop_detected_file" "$pixel_detected_file"
if ! release_join_observe_pair_until_ms \
    "$DESKTOP_ADMIN_DEADLINE_HOST_MS" \
    "$desktop_detected_file" "Linux desktop acceptance query" \
    linux_admin_desktop_visible "$RESULT_DIR/desktop-admin-add-accepted.json" \
    "$pixel_detected_file" "Pixel acceptance query" \
    linux_admin_pixel_visible "$DESKTOP_ADMIN_NPUB"
then
  tail -n 160 "$desktop_add_log" >&2 || true
  echo "Linux desktop and Pixel did not both accept before the shared deadline" >&2
  exit 1
fi
DESKTOP_ACCEPTED_HOST_MS="$(<"$desktop_detected_file")"
PIXEL_ACCEPTED_HOST_MS="$(<"$pixel_detected_file")"
DESKTOP_ACCEPTANCE_MS="$(
  delivery_from_guest_submit \
    "$DESKTOP_SUBMITTED_GUEST" \
    "$DESKTOP_ACCEPTED_HOST_MS" \
    "Linux-admin-desktop-acceptance"
)"
PIXEL_ACCEPTANCE_MS="$(
  delivery_from_guest_submit \
    "$DESKTOP_SUBMITTED_GUEST" \
    "$PIXEL_ACCEPTED_HOST_MS" \
    "Linux-admin-Pixel-acceptance"
)"
if ((DESKTOP_ACCEPTANCE_MS > PIXEL_ACCEPTANCE_MS)); then
  DESKTOP_ADMIN_DELIVERY_MS="$DESKTOP_ACCEPTANCE_MS"
else
  DESKTOP_ADMIN_DELIVERY_MS="$PIXEL_ACCEPTANCE_MS"
fi
release_join_android_relaunch_and_wait_accepted "$DESKTOP_ADMIN_NPUB" || {
  echo "Pixel lost the Linux admin roster across force-stop/relaunch" >&2
  exit 1
}
remote Stop
finish_remote "$desktop_add_log"
remote ReadMarker >"$RESULT_DIR/desktop-admin-add-final.json"
[[ "$(
  marker_value "$RESULT_DIR/desktop-admin-add-final.json" holdReleased
)" == true ]]
remote Verify "$RELEASE_JOIN_ANDROID_JOINER_ID" \
  >"$RESULT_DIR/desktop-admin-relaunch.log"
remote ReadMarker >"$RESULT_DIR/desktop-admin-relaunch.json"
[[ "$(
  marker_value "$RESULT_DIR/desktop-admin-relaunch.json" relaunchAccepted
)" == true ]]

# Physical Pixel admin -> imported Linux desktop joiner.
release_join_reset_android_state
remote Cleanup 1 >"$RESULT_DIR/desktop-admin-service-cleanup.log"
service_cleanup_armed=0
remote Reset >"$RESULT_DIR/desktop-joiner-reset.log"
remote Bootstrap >"$RESULT_DIR/desktop-joiner-bootstrap.log"
remote ReadMarker >"$RESULT_DIR/desktop-joiner-bootstrap.json"
DESKTOP_JOINER_NPUB="$(
  marker_value "$RESULT_DIR/desktop-joiner-bootstrap.json" joinerNpub
)"
release_join_valid_npub "$DESKTOP_JOINER_NPUB"
service_cleanup_armed=1
remote InstallService >"$RESULT_DIR/desktop-joiner-service.log"
release_join_android_create_admin
release_join_android_manual_admin_prepare "$DESKTOP_JOINER_NPUB" \
  >"$RESULT_DIR/pixel-admin-prepare.log" 2>&1

desktop_join_log="$RESULT_DIR/pixel-admin-desktop-join.log"
remote ManualJoin \
  "$RELEASE_JOIN_ANDROID_ADMIN_ID" \
  "$RELEASE_JOIN_ANDROID_NETWORK_ID" \
  >"$desktop_join_log" 2>&1 &
remote_pid=$!
wait_remote_field \
  "$RESULT_DIR/desktop-manual-join-identity.json" \
  joinerNpub __present__ 10 || {
  tail -n 160 "$desktop_join_log" >&2 || true
  exit 1
}
[[ "$(
  marker_value "$RESULT_DIR/desktop-manual-join-identity.json" joinerNpub
)" == "$DESKTOP_JOINER_NPUB" ]] || {
  echo "Linux ManualJoin used a different identity than Bootstrap" >&2
  exit 1
}
wait_remote_field \
  "$RESULT_DIR/desktop-manual-join-submitted.json" \
  manualSubmittedMs __present__ 10 || {
  tail -n 160 "$desktop_join_log" >&2 || true
  exit 1
}
pixel_add_log="$RESULT_DIR/pixel-admin-add-desktop.log"
release_join_android_manual_admin_tap "$DESKTOP_JOINER_NPUB" \
  | tee "$pixel_add_log"
PIXEL_SUBMITTED_HOST="$(
  sed -n \
    's/.*NVPN_RELEASE_JOIN_APPROVAL_SUBMITTED_MS=//p' \
    "$pixel_add_log" \
    | tail -n 1
)"
LINUX_REVERSE_DEADLINE_HOST_MS=$((
  PIXEL_SUBMITTED_HOST + RELEASE_JOIN_DELIVERY_WAIT_SECS * 1000
))
linux_reverse_desktop_file="$RESULT_DIR/pixel-admin-desktop-detected-ms.txt"
linux_reverse_pixel_file="$RESULT_DIR/pixel-admin-pixel-detected-ms.txt"
rm -f "$linux_reverse_desktop_file" "$linux_reverse_pixel_file"
if ! release_join_observe_pair_until_ms \
    "$LINUX_REVERSE_DEADLINE_HOST_MS" \
    "$linux_reverse_desktop_file" "Linux reverse acceptance query" \
    linux_admin_desktop_visible "$RESULT_DIR/desktop-manual-join-accepted.json" \
    "$linux_reverse_pixel_file" "Pixel reverse acceptance query" \
    linux_admin_pixel_visible "$DESKTOP_JOINER_NPUB"
then
  tail -n 160 "$desktop_join_log" >&2 || true
  echo "Linux and Pixel reverse acceptance exceeded their shared deadline" >&2
  exit 1
fi
LINUX_REVERSE_DESKTOP_MS="$(<"$linux_reverse_desktop_file")"
LINUX_REVERSE_PIXEL_MS="$(<"$linux_reverse_pixel_file")"
[[ "$(
  marker_value "$RESULT_DIR/desktop-manual-join-accepted.json" adminNpub
)" == "$RELEASE_JOIN_ANDROID_ADMIN_ID" ]] || {
  echo "Linux joiner accepted the wrong Pixel admin roster" >&2
  exit 1
}
finish_remote "$desktop_join_log"
LINUX_REVERSE_DESKTOP_DELIVERY_MS="$(
  delivery_from_host_submit \
    "$PIXEL_SUBMITTED_HOST" \
    "$LINUX_REVERSE_DESKTOP_MS" \
    "Pixel-admin-Linux-acceptance"
)"
LINUX_REVERSE_PIXEL_DELIVERY_MS="$(
  delivery_from_host_submit \
    "$PIXEL_SUBMITTED_HOST" \
    "$LINUX_REVERSE_PIXEL_MS" \
    "Pixel-admin-Pixel-acceptance"
)"
if ((LINUX_REVERSE_DESKTOP_DELIVERY_MS > LINUX_REVERSE_PIXEL_DELIVERY_MS)); then
  PIXEL_ADMIN_DELIVERY_MS="$LINUX_REVERSE_DESKTOP_DELIVERY_MS"
else
  PIXEL_ADMIN_DELIVERY_MS="$LINUX_REVERSE_PIXEL_DELIVERY_MS"
fi
release_join_android_relaunch_and_wait_accepted "$DESKTOP_JOINER_NPUB" || {
  echo "Pixel lost the Linux joiner roster across force-stop/relaunch" >&2
  exit 1
}
remote Verify "$RELEASE_JOIN_ANDROID_ADMIN_ID" \
  >"$RESULT_DIR/desktop-joiner-relaunch.log"
remote ReadMarker >"$RESULT_DIR/desktop-joiner-relaunch.json"
[[ "$(
  marker_value "$RESULT_DIR/desktop-joiner-relaunch.json" relaunchAccepted
)" == true ]]

release_join_assert_one_android_package
release_join_assert_one_android_process
release_join_assert_app_unchanged "$APP_GIT_SHA" "$APP_GIT_TREE"
release_join_assert_fips_unchanged

python3 - \
  "$PHASE_EVIDENCE" \
  "$RELEASE_JOIN_DELIVERY_WAIT_SECS" \
  "$DESKTOP_ADMIN_DELIVERY_MS" \
  "$PIXEL_ADMIN_DELIVERY_MS" <<'PY'
import json
import os
import pathlib
import sys
import tempfile

path = pathlib.Path(sys.argv[1])
role = {
    "desktopAccepted": True,
    "pixelAccepted": True,
    "desktopRelaunchAccepted": True,
    "pixelRelaunchAccepted": True,
}
payload = {
    "schema": 1,
    "platform": "linux",
    "completionDeadlineSeconds": int(sys.argv[2]),
    "publicUiOnly": True,
    "privateStateRead": False,
    "fixtureInvoked": False,
    "appLaunchArgumentsOrEnvironment": False,
    "acceptedSelectorSemantics": "participant-state-not-pending",
    "desktopAdminPixelJoiner": {
        **role,
        "deliveryMilliseconds": int(sys.argv[3]),
    },
    "pixelAdminDesktopJoiner": {
        **role,
        "deliveryMilliseconds": int(sys.argv[4]),
    },
}
descriptor, temporary_name = tempfile.mkstemp(
    prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
)
temporary = pathlib.Path(temporary_name)
try:
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)
finally:
    temporary.unlink(missing_ok=True)
PY

receipt_binding_args=(
  --desktop-receipt "$RESULT_DIR/import/host-bundle-receipt.json"
  --android-artifact-receipt "$NVPN_RELEASE_JOIN_ANDROID_RECEIPT"
  --android-install-receipt "$RESULT_DIR/android-release-install.json"
  --android-fips-metadata-receipt \
    "$NVPN_RELEASE_JOIN_ANDROID_FIPS_METADATA_RECEIPT"
  --android-apk "$RELEASE_JOIN_ANDROID_APK"
  --phase-evidence "$PHASE_EVIDENCE"
  --expected-desktop-app-sha "$IMPORTED_DESKTOP_APP_SHA"
  --expected-desktop-app-tree "$IMPORTED_DESKTOP_APP_TREE"
  --expected-desktop-fips-sha "$RELEASE_JOIN_FIPS_SHA"
  --expected-desktop-fips-tree "$RELEASE_JOIN_FIPS_TREE"
  --expected-desktop-fips-version "$RELEASE_JOIN_FIPS_VERSION"
  --expected-android-app-sha "$RELEASE_JOIN_ANDROID_APP_SHA"
  --expected-android-app-tree "$RELEASE_JOIN_ANDROID_APP_TREE"
  --expected-android-fips-sha "$RELEASE_JOIN_FIPS_SHA"
  --expected-android-fips-tree "$RELEASE_JOIN_FIPS_TREE"
  --expected-android-fips-version "$RELEASE_JOIN_FIPS_VERSION"
)
if [[ "$RELEASE_JOIN_INSTALL_ANDROID" -eq 0 ]]; then
  receipt_binding_args+=(--allow-verified-no-install)
fi
python3 "$ROOT/scripts/desktop_mobile_manual_join_receipt.py" create \
  --platform linux \
  "${receipt_binding_args[@]}" \
  --output "$SUMMARY"
python3 "$ROOT/scripts/desktop_mobile_manual_join_receipt.py" validate \
  --platform linux \
  --receipt "$SUMMARY" \
  "${receipt_binding_args[@]}"

echo "SIGNED_RELEASE_PUBLIC_UI_LINUX_PIXEL_MANUAL_JOIN_E2E_OK $SUMMARY"
