#!/usr/bin/env bash
# Exact Windows Release <-> physical Pixel manual join in both role directions.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "$ROOT/scripts/release_common.sh"
# shellcheck disable=SC1091
source "$ROOT/scripts/mobile_env.sh"
# shellcheck disable=SC1091
source "$ROOT/scripts/lib-mobile-release-join-artifacts.sh"
# shellcheck disable=SC1091
source "$ROOT/scripts/lib-mobile-release-join-ui.sh"

load_release_env "$ROOT"
load_env_file_defaults "${NVPN_ZAPSTORE_ENV_FILE:-$ROOT/.env.zapstore.local}"
load_mobile_env "$ROOT"

[[ "$(uname -s)" == Darwin ]] || {
  echo "Windows/Pixel Release join gate must be controlled by macOS" >&2
  exit 2
}
[[ -z "$(git -C "$ROOT" status --porcelain --untracked-files=all)" ]] || {
  echo "Windows/Pixel Release join gate requires a clean committed candidate" >&2
  exit 2
}
APP_GIT_SHA="$(git -C "$ROOT" rev-parse HEAD)"
APP_GIT_TREE="$(git -C "$ROOT" rev-parse 'HEAD^{tree}')"
[[ "${NVPN_EXPECTED_APP_GIT_SHA:-}" =~ ^[0-9a-f]{40}$ \
  && "$APP_GIT_SHA" == "$NVPN_EXPECTED_APP_GIT_SHA" ]] || {
  echo "Set NVPN_EXPECTED_APP_GIT_SHA to the exact committed candidate" >&2
  exit 2
}
if [[ -n "${NVPN_EXPECTED_APP_GIT_TREE:-}" \
  && "$APP_GIT_TREE" != "$NVPN_EXPECTED_APP_GIT_TREE" ]]
then
  echo "Windows/Pixel candidate tree differs from NVPN_EXPECTED_APP_GIT_TREE" >&2
  exit 2
fi

SSH_HOST="${NVPN_WINDOWS_SSH_HOST:-${1:-}}"
SSH_JUMP="${NVPN_WINDOWS_SSH_JUMP:-}"
SSH_PROXY_COMMAND="${NVPN_WINDOWS_SSH_PROXY_COMMAND:-}"
GUEST_REPO="${NVPN_WINDOWS_GUEST_REPO_PATH:-C:\\src\\nostr-vpn}"
GUEST_FIPS_REPO="${NVPN_WINDOWS_GUEST_FIPS_REPO_PATH:-C:\\src\\fips}"
GUEST_ARTIFACT_ROOT="${NVPN_WINDOWS_RELEASE_JOIN_ARTIFACT_ROOT:-C:\\src\\nostr-vpn\\artifacts\\windows-release-mobile-join}"
GUEST_APP="${NVPN_WINDOWS_RELEASE_APP_PATH:-C:\\src\\nostr-vpn\\windows\\NostrVpn.Windows\\bin\\Release\\net8.0-windows\\win-x64\\publish\\NostrVpn.Windows.exe}"
REMOTE_SCRIPT="$GUEST_REPO\\scripts\\windows-release-mobile-join-remote.ps1"
[[ -n "$SSH_HOST" ]] || {
  echo "Set NVPN_WINDOWS_SSH_HOST for Windows/Pixel Release join coverage" >&2
  exit 2
}

RESULT_DIR="${NVPN_RELEASE_JOIN_RESULT_DIR:-$ROOT/artifacts/mobile-release-join}"
PLATFORM_RESULT="$RESULT_DIR/windows"
PRIVATE_DIR="$PLATFORM_RESULT/.private-$$"
ANDROID_INSTALL_RECEIPT="${NVPN_RELEASE_JOIN_ANDROID_INSTALL_RECEIPT:-$RESULT_DIR/android-release-install.json}"
ANDROID_ARTIFACT_RECEIPT="${NVPN_RELEASE_JOIN_ANDROID_RECEIPT:-}"
ANDROID_FIPS_METADATA_RECEIPT="${NVPN_RELEASE_JOIN_ANDROID_FIPS_METADATA_RECEIPT:-}"
DESKTOP_RECEIPT="$PLATFORM_RESULT/windows-release-artifact.json"
PHASE_EVIDENCE="$PLATFORM_RESULT/phase-evidence.json"
SUMMARY="$PLATFORM_RESULT/summary.json"
RELEASE_JOIN_UI_WAIT_SECS="${NVPN_RELEASE_JOIN_UI_WAIT_SECS:-15}"
RELEASE_JOIN_DELIVERY_WAIT_SECS="${NVPN_RELEASE_JOIN_DELIVERY_WAIT_SECS:-15}"
mkdir -p "$PRIVATE_DIR" "$PLATFORM_RESULT"
chmod 700 "$PRIVATE_DIR"

fail() {
  echo "Windows/Pixel signed Release join gate failed: $*" >&2
  exit 1
}

[[ "$RELEASE_JOIN_DELIVERY_WAIT_SECS" =~ ^[1-9][0-9]*$ ]] \
  || fail "delivery timeout must be a positive integer"
((RELEASE_JOIN_DELIVERY_WAIT_SECS <= 15)) \
  || fail "delivery timeout cannot exceed 15 seconds"

release_join_require_clean_fips
[[ -n "${RELEASE_JOIN_ANDROID_APK:-}" \
  && -f "$RELEASE_JOIN_ANDROID_APK" ]] \
  || fail "exact Android Release APK is not inherited from the mobile artifact lane"
[[ -f "$ANDROID_INSTALL_RECEIPT" ]] \
  || fail "Android Release install receipt is missing"
[[ -f "$ANDROID_ARTIFACT_RECEIPT" ]] \
  || fail "Android Release artifact receipt is missing"
[[ -f "$ANDROID_FIPS_METADATA_RECEIPT" ]] \
  || fail "Android FIPS metadata receipt is missing"
ANDROID_APP_SHA="$(jq -er '.appGitSha' "$ANDROID_ARTIFACT_RECEIPT")"
ANDROID_APP_TREE="$(jq -er '.appGitTree' "$ANDROID_ARTIFACT_RECEIPT")"
ANDROID_FIPS_SHA="$(jq -er '.fipsGitSha' "$ANDROID_ARTIFACT_RECEIPT")"
ANDROID_FIPS_TREE="$(jq -er '.fipsGitTree' "$ANDROID_ARTIFACT_RECEIPT")"
ANDROID_FIPS_VERSION="$(jq -er '.fipsCoreVersion' "$ANDROID_ARTIFACT_RECEIPT")"
ANDROID_APK_SHA="$(
  python3 "$ROOT/scripts/desktop_mobile_manual_join_receipt.py" \
    validate-android \
    --receipt "$ANDROID_INSTALL_RECEIPT" \
    --android-artifact-receipt "$ANDROID_ARTIFACT_RECEIPT" \
    --android-fips-metadata-receipt "$ANDROID_FIPS_METADATA_RECEIPT" \
    --apk "$RELEASE_JOIN_ANDROID_APK" \
    --expected-android-app-sha "$ANDROID_APP_SHA" \
    --expected-android-app-tree "$ANDROID_APP_TREE" \
    --expected-android-fips-sha "$ANDROID_FIPS_SHA" \
    --expected-android-fips-tree "$ANDROID_FIPS_TREE" \
    --expected-android-fips-version "$ANDROID_FIPS_VERSION"
)" || fail "Android artifact provenance validation failed"
[[ "$ANDROID_FIPS_SHA" == "$RELEASE_JOIN_FIPS_SHA" \
  && "$ANDROID_FIPS_TREE" == "$RELEASE_JOIN_FIPS_TREE" \
  && "$ANDROID_FIPS_VERSION" == "$RELEASE_JOIN_FIPS_VERSION" ]] \
  || fail "Android artifact uses a different FIPS component"
[[ "$ANDROID_APK_SHA" =~ ^[0-9a-f]{64}$ ]] \
  || fail "Android artifact verifier returned an invalid hash"
if [[ -n "${RELEASE_JOIN_ANDROID_APK_SHA:-}" \
  && "$RELEASE_JOIN_ANDROID_APK_SHA" != "$ANDROID_APK_SHA" ]]
then
  fail "inherited Android APK hash differs from its install receipt"
fi
RELEASE_JOIN_ARTIFACTS_VALIDATED=1
export RELEASE_JOIN_ARTIFACTS_VALIDATED

ANDROID_REQUESTED="${NVPN_ANDROID_SERIAL:-${ANDROID_SERIAL:-}}"
[[ -n "$ANDROID_REQUESTED" ]] \
  || fail "set NVPN_ANDROID_SERIAL to the exact physical Pixel"
ANDROID_SERIAL_SELECTED="$(
  select_physical_android_serial \
    "${ADB_BIN:-adb}" \
    "$ANDROID_REQUESTED"
)" || fail "one physical Android phone is required"
ADB=("${ADB_BIN:-adb}" -s "$ANDROID_SERIAL_SELECTED")
export NVPN_ANDROID_SERIAL="$ANDROID_SERIAL_SELECTED"
export RESULT_DIR PRIVATE_DIR RELEASE_JOIN_UI_WAIT_SECS
export RELEASE_JOIN_DELIVERY_WAIT_SECS
RELEASE_JOIN_DEVICE_MUTATION_ALLOWED=1
export RELEASE_JOIN_DEVICE_MUTATION_ALLOWED
release_join_assert_one_android_package

ssh_command() {
  SSH_CMD=(ssh -o BatchMode=yes -o ConnectTimeout=10)
  if [[ -n "$SSH_PROXY_COMMAND" ]]; then
    SSH_CMD+=(-o "ProxyCommand=$SSH_PROXY_COMMAND")
  elif [[ -n "$SSH_JUMP" ]]; then
    SSH_CMD+=(-J "$SSH_JUMP")
  fi
  SSH_CMD+=("$SSH_HOST")
}

run_ps() {
  local script="$1" encoded
  encoded="$(
    printf '%s' "$script" \
      | iconv -t UTF-16LE \
      | base64 \
      | tr -d '\n'
  )"
  ssh_command
  "${SSH_CMD[@]}" powershell.exe \
    -NoProfile -NonInteractive -ExecutionPolicy Bypass \
    -EncodedCommand "$encoded"
}

ps_quote() {
  local value="${1//\'/\'\'}"
  printf "'%s'" "$value"
}

REMOTE_NETWORK_NAME=""
REMOTE_ADMIN_NPUB=""
REMOTE_NETWORK_ID=""
REMOTE_PARTICIPANT_NPUB=""
REMOTE_PARTICIPANT_ALIAS=""

remote() {
  local mode="$1" command
  printf -v command \
    "\$ErrorActionPreference = 'Stop'\n& %s -Mode %s -RepoRoot %s -ArtifactRoot %s -AppExe %s -FipsRepo %s -ExpectedAppGitSha %s -ExpectedAppGitTree %s -ExpectedFipsGitSha %s -ExpectedFipsGitTree %s -ExpectedFipsVersion %s -NetworkName %s -AdminNpub %s -NetworkId %s -ParticipantNpub %s -ParticipantAlias %s" \
    "$(ps_quote "$REMOTE_SCRIPT")" \
    "$(ps_quote "$mode")" \
    "$(ps_quote "$GUEST_REPO")" \
    "$(ps_quote "$GUEST_ARTIFACT_ROOT")" \
    "$(ps_quote "$GUEST_APP")" \
    "$(ps_quote "$GUEST_FIPS_REPO")" \
    "$(ps_quote "$APP_GIT_SHA")" \
    "$(ps_quote "$APP_GIT_TREE")" \
    "$(ps_quote "$RELEASE_JOIN_FIPS_SHA")" \
    "$(ps_quote "$RELEASE_JOIN_FIPS_TREE")" \
    "$(ps_quote "$RELEASE_JOIN_FIPS_VERSION")" \
    "$(ps_quote "$REMOTE_NETWORK_NAME")" \
    "$(ps_quote "$REMOTE_ADMIN_NPUB")" \
    "$(ps_quote "$REMOTE_NETWORK_ID")" \
    "$(ps_quote "$REMOTE_PARTICIPANT_NPUB")" \
    "$(ps_quote "$REMOTE_PARTICIPANT_ALIAS")"
  run_ps "$command"
}

REMOTE_ACTION_PID=""
acceptance_observer_pids=()
cleanup() {
  local status=$?
  trap - EXIT
  local observer_pid cleanup_status=0
  for observer_pid in "${acceptance_observer_pids[@]-}"; do
    kill "$observer_pid" >/dev/null 2>&1 || true
    wait "$observer_pid" >/dev/null 2>&1 || true
  done
  if [[ -n "$REMOTE_ACTION_PID" ]] \
    && kill -0 "$REMOTE_ACTION_PID" >/dev/null 2>&1
  then
    remote Stop >/dev/null 2>&1 || true
    wait "$REMOTE_ACTION_PID" >/dev/null 2>&1 || true
  fi
  if [[ "$status" -ne 0 ]]; then
    remote ReadDaemonLog >"$PLATFORM_RESULT/windows-daemon-failure.log" \
      2>&1 || true
  fi
  remote Cleanup >"$PLATFORM_RESULT/windows-cleanup.log" 2>&1 \
    || cleanup_status=$?
  if [[ "$status" -ne 0 && -s "$PRIVATE_DIR/android-ui.xml" ]]; then
    cp "$PRIVATE_DIR/android-ui.xml" "$PLATFORM_RESULT/android-ui-failure.xml"
  fi
  rm -rf "$PRIVATE_DIR"
  if ((status == 0 && cleanup_status != 0)); then
    status=$cleanup_status
  fi
  exit "$status"
}
trap cleanup EXIT

case "${NVPN_WINDOWS_SKIP_GIT_SYNC:-0}" in
  1|true|TRUE|True|yes|YES|Yes|on|ON|On) ;;
  *)
    NVPN_WINDOWS_FIPS_REPO_PATH="$NVPN_FIPS_REPO_PATH" \
      "$ROOT/scripts/windows-vm-git-sync.sh" "$SSH_HOST"
    ;;
esac

remote Prepare 2>&1 | tee "$PLATFORM_RESULT/prepare.log"
remote ReadReceipt >"$DESKTOP_RECEIPT"

read_marker() {
  remote ReadMarker 2>/dev/null
}

MARKER_PAYLOAD=""
wait_marker() {
  local filter="$1" label="$2"
  local timeout="${3:-$RELEASE_JOIN_UI_WAIT_SECS}"
  local deadline=$((SECONDS + timeout)) payload
  while ((SECONDS < deadline)); do
    if payload="$(read_marker)" \
      && jq -e "$filter" <<<"$payload" >/dev/null 2>&1
    then
      MARKER_PAYLOAD="$payload"
      return 0
    fi
    if [[ -n "$REMOTE_ACTION_PID" ]] \
      && ! kill -0 "$REMOTE_ACTION_PID" >/dev/null 2>&1
    then
      wait "$REMOTE_ACTION_PID" || true
      REMOTE_ACTION_PID=""
      fail "Windows interactive action exited before $label"
    fi
    sleep 0.1
  done
  fail "Windows marker did not report $label within ${timeout}s"
}

finish_remote_action() {
  local log="$1" status=0
  [[ -n "$REMOTE_ACTION_PID" ]] || fail "no Windows action is running"
  wait "$REMOTE_ACTION_PID" || status=$?
  REMOTE_ACTION_PID=""
  if [[ "$status" -ne 0 ]]; then
    tail -n 160 "$log" >&2 || true
    fail "Windows interactive action failed"
  fi
}

assert_elapsed() {
  local submitted="$1" completed="$2" label="$3"
  [[ "$submitted" =~ ^[0-9]+$ && "$completed" =~ ^[0-9]+$ ]] \
    || fail "$label has invalid timestamps"
  local elapsed=$((completed - submitted))
  ((elapsed >= 0 && elapsed <= RELEASE_JOIN_DELIVERY_WAIT_SECS * 1000)) \
    || fail "$label took ${elapsed}ms after approval"
  printf '%s\n' "$elapsed"
}

WINDOWS_CLOCK_OFFSET_MS=0
WINDOWS_CLOCK_UNCERTAINTY_MS=0

calibrate_windows_clock() {
  local best_rtt=999999 best_offset=0 before after guest rtt offset
  for _ in 1 2 3; do
    before="$(release_join_now_ms)"
    guest="$(remote NowMs | tr -d '\r' | tail -n 1)"
    after="$(release_join_now_ms)"
    [[ "$guest" =~ ^[0-9]+$ ]] || fail "Windows clock did not report epoch milliseconds"
    rtt=$((after - before))
    offset=$((((before + after) / 2) - guest))
    if ((rtt < best_rtt)); then
      best_rtt="$rtt"
      best_offset="$offset"
    fi
  done
  WINDOWS_CLOCK_OFFSET_MS="$best_offset"
  WINDOWS_CLOCK_UNCERTAINTY_MS=$(((best_rtt + 1) / 2 + 250))
  ((WINDOWS_CLOCK_UNCERTAINTY_MS <= 2000)) \
    || fail "Windows clock calibration uncertainty is too high"
}

windows_delivery_from_guest_submit() {
  local submitted_guest="$1" detected_host="$2" label="$3"
  local elapsed=$((
    detected_host - (submitted_guest + WINDOWS_CLOCK_OFFSET_MS) \
      + WINDOWS_CLOCK_UNCERTAINTY_MS
  ))
  ((elapsed >= 0 && elapsed <= RELEASE_JOIN_DELIVERY_WAIT_SECS * 1000)) \
    || fail "$label took conservatively ${elapsed}ms after approval"
  printf '%s\n' "$elapsed"
}

windows_admin_desktop_visible() {
  local output="$1" temporary="$1.tmp" accepted_guest
  read_marker >"$temporary" \
    && jq -e \
      --arg mode "$WINDOWS_ACCEPTANCE_MODE" \
      '.mode == $mode and .desktopAccepted == true' \
      "$temporary" >/dev/null \
    && accepted_guest="$(jq -er '.acceptedAtMs' "$temporary")" \
    && mv "$temporary" "$output" \
    && printf '%s\n' "$((accepted_guest + WINDOWS_CLOCK_OFFSET_MS))"
}

windows_admin_pixel_visible() {
  release_join_android_accepted_snapshot_ms "$1"
}

verify_desktop_relaunch() {
  local participant="$1" label="$2" marker
  REMOTE_PARTICIPANT_NPUB="$participant"
  remote Verify >"$PLATFORM_RESULT/$label-relaunch.log" 2>&1
  marker="$(read_marker)"
  jq -e \
    --arg participant "$participant" \
    '.mode == "Verify"
      and .publicUiOnly == true
      and .privateStateRead == false
      and .relaunchAccepted == true
      and .participantNpub == $participant' \
    <<<"$marker" >/dev/null \
    || fail "$label desktop relaunch did not show the exact accepted roster"
}

verify_pixel_relaunch() {
  local participant="$1" label="$2"
  local package="${NVPN_DEFAULT_APP_ID:-fi.siriusbusiness.nvpn}"
  "${ADB[@]}" shell am force-stop "$package" >/dev/null
  release_join_android_launch >/dev/null
  release_join_android_wait_accepted_participant "$participant" \
    || fail "$label Pixel relaunch did not show the exact accepted roster"
}

calibrate_windows_clock

# Windows admin -> Pixel joiner.
release_join_reset_android_state
remote Reset >"$PLATFORM_RESULT/desktop-admin-reset.log" 2>&1
REMOTE_NETWORK_NAME="Release Windows admin"
remote CreateAdmin >"$PLATFORM_RESULT/desktop-admin-create.log" 2>&1
admin_marker="$(read_marker)"
WINDOWS_ADMIN_ID="$(jq -er '.adminNpub' <<<"$admin_marker")"
WINDOWS_NETWORK_ID="$(jq -er '.networkId' <<<"$admin_marker")"
release_join_valid_npub "$WINDOWS_ADMIN_ID" \
  || fail "Windows UI did not expose a valid admin Device ID"
[[ -n "$WINDOWS_NETWORK_ID" ]] \
  || fail "Windows UI did not expose a Network ID"
remote InstallService >"$PLATFORM_RESULT/desktop-admin-service.log" 2>&1

release_join_android_manual_submit "$WINDOWS_ADMIN_ID" "$WINDOWS_NETWORK_ID" \
  >"$PLATFORM_RESULT/pixel-manual-submit.log" 2>&1
REMOTE_PARTICIPANT_NPUB="$RELEASE_JOIN_ANDROID_JOINER_ID"
REMOTE_PARTICIPANT_ALIAS="Release Pixel"
desktop_admin_log="$PLATFORM_RESULT/desktop-admin-add.log"
remote AdminAdd >"$desktop_admin_log" 2>&1 &
REMOTE_ACTION_PID=$!
wait_marker \
  '.mode == "AdminAdd"
    and (.approvalSubmittedMs | type == "number")
    and .participantNpub != ""' \
  "Windows admin approval submission"
admin_submission_marker="$MARKER_PAYLOAD"
WINDOWS_APPROVAL_MS="$(jq -er '.approvalSubmittedMs' <<<"$admin_submission_marker")"
WINDOWS_ADMIN_DEADLINE_HOST_MS=$((
  WINDOWS_APPROVAL_MS + WINDOWS_CLOCK_OFFSET_MS \
    + RELEASE_JOIN_DELIVERY_WAIT_SECS * 1000
))
windows_desktop_detected_file="$PLATFORM_RESULT/desktop-admin-desktop-detected-ms.txt"
windows_pixel_detected_file="$PLATFORM_RESULT/desktop-admin-pixel-detected-ms.txt"
rm -f "$windows_desktop_detected_file" "$windows_pixel_detected_file"
WINDOWS_ACCEPTANCE_MODE=AdminAdd
release_join_observe_pair_until_ms \
  "$WINDOWS_ADMIN_DEADLINE_HOST_MS" \
  "$windows_desktop_detected_file" "Windows desktop acceptance query" \
  windows_admin_desktop_visible "$PLATFORM_RESULT/desktop-admin-accepted.json" \
  "$windows_pixel_detected_file" "Pixel acceptance query" \
  windows_admin_pixel_visible "$WINDOWS_ADMIN_ID" \
  || fail "Windows desktop and Pixel did not both accept before the shared deadline"
WINDOWS_DESKTOP_ACCEPTED_HOST_MS="$(<"$windows_desktop_detected_file")"
WINDOWS_PIXEL_ACCEPTED_HOST_MS="$(<"$windows_pixel_detected_file")"
WINDOWS_DESKTOP_ACCEPTANCE_MS="$(
  windows_delivery_from_guest_submit \
    "$WINDOWS_APPROVAL_MS" \
    "$WINDOWS_DESKTOP_ACCEPTED_HOST_MS" \
    "Windows-admin-desktop-acceptance"
)"
WINDOWS_PIXEL_ACCEPTANCE_MS="$(
  windows_delivery_from_guest_submit \
    "$WINDOWS_APPROVAL_MS" \
    "$WINDOWS_PIXEL_ACCEPTED_HOST_MS" \
    "Windows-admin-Pixel-acceptance"
)"
if ((WINDOWS_DESKTOP_ACCEPTANCE_MS > WINDOWS_PIXEL_ACCEPTANCE_MS)); then
  WINDOWS_ADMIN_DELIVERY_MS="$WINDOWS_DESKTOP_ACCEPTANCE_MS"
else
  WINDOWS_ADMIN_DELIVERY_MS="$WINDOWS_PIXEL_ACCEPTANCE_MS"
fi
desktop_admin_accepted_marker="$(<"$PLATFORM_RESULT/desktop-admin-accepted.json")"
jq -e \
  --arg participant "$RELEASE_JOIN_ANDROID_JOINER_ID" \
  '.participantNpub == $participant' \
  <<<"$desktop_admin_accepted_marker" >/dev/null \
  || fail "Windows admin accepted the wrong roster participant"
remote Stop >/dev/null
finish_remote_action "$desktop_admin_log"
verify_desktop_relaunch \
  "$RELEASE_JOIN_ANDROID_JOINER_ID" "desktop-admin"
verify_pixel_relaunch "$WINDOWS_ADMIN_ID" "desktop-admin"

# Pixel admin -> Windows joiner.
release_join_reset_android_state
REMOTE_PARTICIPANT_NPUB=""
remote Reset >"$PLATFORM_RESULT/desktop-joiner-reset.log" 2>&1
remote Bootstrap >"$PLATFORM_RESULT/desktop-joiner-bootstrap.log" 2>&1
desktop_joiner_bootstrap_marker="$(read_marker)"
WINDOWS_JOINER_ID="$(
  jq -er '.joinerNpub' <<<"$desktop_joiner_bootstrap_marker"
)"
release_join_valid_npub "$WINDOWS_JOINER_ID" \
  || fail "Windows bootstrap did not expose a valid joiner Device ID"
remote InstallService >"$PLATFORM_RESULT/desktop-joiner-service.log" 2>&1
release_join_android_create_admin
release_join_android_manual_admin_prepare "$WINDOWS_JOINER_ID" \
  >"$PLATFORM_RESULT/pixel-admin-prepare.log" 2>&1

REMOTE_ADMIN_NPUB="$RELEASE_JOIN_ANDROID_ADMIN_ID"
REMOTE_NETWORK_ID="$RELEASE_JOIN_ANDROID_NETWORK_ID"
desktop_joiner_log="$PLATFORM_RESULT/desktop-joiner-manual.log"
remote ManualJoin >"$desktop_joiner_log" 2>&1 &
REMOTE_ACTION_PID=$!
wait_marker \
  '.mode == "ManualJoin"
    and (.manualSubmittedMs | type == "number")
    and .joinerNpub != ""' \
  "Windows manual-join submission"
join_submission_marker="$MARKER_PAYLOAD"
jq -e --arg joiner "$WINDOWS_JOINER_ID" \
  '.joinerNpub == $joiner' <<<"$join_submission_marker" >/dev/null \
  || fail "Windows ManualJoin used a different identity than Bootstrap"

android_approval_log="$PLATFORM_RESULT/pixel-admin-add.log"
release_join_android_manual_admin_tap "$WINDOWS_JOINER_ID" \
  | tee "$android_approval_log"
PIXEL_APPROVAL_MS="$(
  sed -n \
    's/.*NVPN_RELEASE_JOIN_APPROVAL_SUBMITTED_MS=//p' \
    "$android_approval_log" \
    | tail -n 1
)"
[[ "$PIXEL_APPROVAL_MS" =~ ^[0-9]+$ ]] \
  || fail "Pixel admin UI did not report its real approval timestamp"
WINDOWS_REVERSE_DEADLINE_HOST_MS=$((
  PIXEL_APPROVAL_MS + RELEASE_JOIN_DELIVERY_WAIT_SECS * 1000
))
windows_reverse_desktop_file="$PLATFORM_RESULT/pixel-admin-desktop-detected-ms.txt"
windows_reverse_pixel_file="$PLATFORM_RESULT/pixel-admin-pixel-detected-ms.txt"
rm -f "$windows_reverse_desktop_file" "$windows_reverse_pixel_file"
WINDOWS_ACCEPTANCE_MODE=ManualJoin
release_join_observe_pair_until_ms \
  "$WINDOWS_REVERSE_DEADLINE_HOST_MS" \
  "$windows_reverse_desktop_file" "Windows reverse acceptance query" \
  windows_admin_desktop_visible "$PLATFORM_RESULT/desktop-joiner-accepted.json" \
  "$windows_reverse_pixel_file" "Pixel reverse acceptance query" \
  windows_admin_pixel_visible "$WINDOWS_JOINER_ID" \
  || fail "Windows and Pixel reverse acceptance exceeded their shared deadline"
WINDOWS_REVERSE_DESKTOP_MS="$(<"$windows_reverse_desktop_file")"
WINDOWS_REVERSE_PIXEL_MS="$(<"$windows_reverse_pixel_file")"
desktop_joiner_accepted_marker="$(<"$PLATFORM_RESULT/desktop-joiner-accepted.json")"
jq -e \
  --arg admin "$RELEASE_JOIN_ANDROID_ADMIN_ID" \
  '.adminNpub == $admin' \
  <<<"$desktop_joiner_accepted_marker" >/dev/null \
  || fail "Windows joiner accepted the wrong Pixel admin roster"
WINDOWS_REVERSE_DESKTOP_DELIVERY_MS="$(
  assert_elapsed \
    "$PIXEL_APPROVAL_MS" \
    "$WINDOWS_REVERSE_DESKTOP_MS" \
    "Pixel-admin-Windows-acceptance"
)"
WINDOWS_REVERSE_PIXEL_DELIVERY_MS="$(
  assert_elapsed \
    "$PIXEL_APPROVAL_MS" \
    "$WINDOWS_REVERSE_PIXEL_MS" \
    "Pixel-admin-Pixel-acceptance"
)"
if ((WINDOWS_REVERSE_DESKTOP_DELIVERY_MS > WINDOWS_REVERSE_PIXEL_DELIVERY_MS)); then
  PIXEL_ADMIN_DELIVERY_MS="$WINDOWS_REVERSE_DESKTOP_DELIVERY_MS"
else
  PIXEL_ADMIN_DELIVERY_MS="$WINDOWS_REVERSE_PIXEL_DELIVERY_MS"
fi
finish_remote_action "$desktop_joiner_log"
verify_desktop_relaunch \
  "$RELEASE_JOIN_ANDROID_ADMIN_ID" "desktop-joiner"
verify_pixel_relaunch "$WINDOWS_JOINER_ID" "desktop-joiner"

release_join_assert_one_android_package
release_join_assert_one_android_process

python3 - \
  "$PHASE_EVIDENCE" \
  "$WINDOWS_ADMIN_DELIVERY_MS" \
  "$PIXEL_ADMIN_DELIVERY_MS" \
  "$RELEASE_JOIN_DELIVERY_WAIT_SECS" <<'PY'
import json
import os
import pathlib
import sys
import tempfile

output, windows_admin_ms, pixel_admin_ms, deadline = sys.argv[1:]
payload = {
    "schema": 1,
    "platform": "windows",
    "completionDeadlineSeconds": int(deadline),
    "publicUiOnly": True,
    "privateStateRead": False,
    "fixtureInvoked": False,
    "appLaunchArgumentsOrEnvironment": False,
    "acceptedSelectorSemantics": "participant-state-not-pending",
    "desktopAdminPixelJoiner": {
        "desktopAccepted": True,
        "pixelAccepted": True,
        "desktopRelaunchAccepted": True,
        "pixelRelaunchAccepted": True,
        "deliveryMilliseconds": int(windows_admin_ms),
    },
    "pixelAdminDesktopJoiner": {
        "desktopAccepted": True,
        "pixelAccepted": True,
        "desktopRelaunchAccepted": True,
        "pixelRelaunchAccepted": True,
        "deliveryMilliseconds": int(pixel_admin_ms),
    },
}
path = pathlib.Path(output)
fd, temporary_name = tempfile.mkstemp(
    prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
)
temporary = pathlib.Path(temporary_name)
try:
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)
finally:
    temporary.unlink(missing_ok=True)
PY

receipt_binding_args=(
  --desktop-receipt "$DESKTOP_RECEIPT"
  --android-artifact-receipt "$ANDROID_ARTIFACT_RECEIPT"
  --android-install-receipt "$ANDROID_INSTALL_RECEIPT"
  --android-fips-metadata-receipt "$ANDROID_FIPS_METADATA_RECEIPT"
  --android-apk "$RELEASE_JOIN_ANDROID_APK"
  --phase-evidence "$PHASE_EVIDENCE"
  --expected-desktop-app-sha "$APP_GIT_SHA"
  --expected-desktop-app-tree "$APP_GIT_TREE"
  --expected-desktop-fips-sha "$RELEASE_JOIN_FIPS_SHA"
  --expected-desktop-fips-tree "$RELEASE_JOIN_FIPS_TREE"
  --expected-desktop-fips-version "$RELEASE_JOIN_FIPS_VERSION"
  --expected-android-app-sha "$ANDROID_APP_SHA"
  --expected-android-app-tree "$ANDROID_APP_TREE"
  --expected-android-fips-sha "$ANDROID_FIPS_SHA"
  --expected-android-fips-tree "$ANDROID_FIPS_TREE"
  --expected-android-fips-version "$ANDROID_FIPS_VERSION"
)
python3 "$ROOT/scripts/desktop_mobile_manual_join_receipt.py" create \
  --platform windows \
  "${receipt_binding_args[@]}" \
  --output "$SUMMARY"
python3 "$ROOT/scripts/desktop_mobile_manual_join_receipt.py" validate \
  --platform windows \
  --receipt "$SUMMARY" \
  "${receipt_binding_args[@]}"

echo "SIGNED_RELEASE_PUBLIC_UI_WINDOWS_PIXEL_MANUAL_JOIN_E2E_OK $SUMMARY"
