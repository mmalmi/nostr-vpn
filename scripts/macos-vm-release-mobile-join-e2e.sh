#!/usr/bin/env bash
# Signed macOS Release <-> physical Android/iPhone manual join in both roles.
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
# shellcheck disable=SC1091
source "$ROOT/scripts/lib-mobile-ios-release-network.sh"
# shellcheck disable=SC1091
source "$ROOT/scripts/lib-macos-release-app-ownership.sh"
# shellcheck disable=SC1091
source "$ROOT/scripts/lib-macos-vm-identity.sh"
load_release_env "$ROOT"
load_env_file_defaults "${NVPN_ZAPSTORE_ENV_FILE:-$ROOT/.env.zapstore.local}"
load_mobile_env "$ROOT"
ARTIFACT_ACTION="${NVPN_MACOS_RELEASE_ARTIFACT_ACTION:-full}"
case "$ARTIFACT_ACTION" in
  full|prepare-only|verify-only|run-only) ;;
  *)
    echo "Unsupported NVPN_MACOS_RELEASE_ARTIFACT_ACTION=$ARTIFACT_ACTION" >&2
    exit 2
    ;;
esac
MACOS_MOBILE_DIRECTIONS="${NVPN_MACOS_RELEASE_MOBILE_DIRECTIONS:-all}"
case "$MACOS_MOBILE_DIRECTIONS" in
  all|pixel) ;;
  *)
    echo "Unsupported NVPN_MACOS_RELEASE_MOBILE_DIRECTIONS=$MACOS_MOBILE_DIRECTIONS (expected all or pixel)" >&2
    exit 2
    ;;
esac
MACOS_RUST_PROFILE="${NVPN_MACOS_RUST_PROFILE:-release}"
MACOS_XCODE_CONFIGURATION="${NVPN_MACOS_XCODE_CONFIGURATION:-Release}"
if [[ "$MACOS_RUST_PROFILE" != "release" \
  || "$MACOS_XCODE_CONFIGURATION" != "Release" ]]
then
  echo "macOS Release gate artifacts require Rust release and Xcode Release builds" >&2
  exit 2
fi

MACOS_SIGNING_IDENTITY="$(
  printf '%s' "${MACOS_SIGNING_IDENTITY:-}" \
    | tr -d ':[:space:]' \
    | tr '[:lower:]' '[:upper:]'
)"
EXPECTED_MACOS_TEAM="${NVPN_EXPECTED_MACOS_SIGNING_TEAM_ID:-${NVPN_IOS_TEAM_ID:-}}"
EXPECTED_MACOS_CERT="$(
  printf '%s' "${NVPN_EXPECTED_MACOS_SIGNER_CERT_SHA256:-}" \
    | tr -d ':[:space:]' \
    | tr '[:upper:]' '[:lower:]'
)"
[[ "$MACOS_SIGNING_IDENTITY" =~ ^[0-9A-F]{40}$ ]] || {
  echo "Set MACOS_SIGNING_IDENTITY to the exact Developer ID certificate SHA-1" >&2
  exit 2
}
[[ "$EXPECTED_MACOS_TEAM" =~ ^[A-Z0-9]{10}$ ]] || {
  echo "Set NVPN_IOS_TEAM_ID or NVPN_EXPECTED_MACOS_SIGNING_TEAM_ID" >&2
  exit 2
}
if [[ -z "$EXPECTED_MACOS_CERT" ]]; then
  EXPECTED_MACOS_CERT="$(
    python3 "$ROOT/scripts/macos_release_join_artifact.py" \
      resolve-certificate --identity-sha1 "$MACOS_SIGNING_IDENTITY"
  )"
fi
[[ "$EXPECTED_MACOS_CERT" =~ ^[0-9a-f]{64}$ ]] || {
  echo "Set NVPN_EXPECTED_MACOS_SIGNER_CERT_SHA256 to the exact Developer ID certificate" >&2
  exit 2
}

MAC_HOST="${NVPN_MACOS_SSH_HOST:-${1:-}}"
[[ -n "$MAC_HOST" ]] || {
  echo "Set NVPN_MACOS_SSH_HOST for Release desktop/mobile join coverage" >&2
  exit 2
}
macos_vm_require_isolated_target "$MAC_HOST"
GUEST_SRC_ROOT="${NVPN_MACOS_GUEST_SRC_ROOT:-src}"
GUEST_REPO="$GUEST_SRC_ROOT/nostr-vpn"
REMOTE_HARNESS_FILES=(
  scripts/lib-macos-release-app-ownership.sh
  scripts/macos-release-mobile-join-remote.sh
  scripts/macos_release_join_artifact.py
  scripts/mobile_release_artifact_receipt.py
)
REMOTE_HARNESS_DIGEST="$(
  for file in "${REMOTE_HARNESS_FILES[@]}"; do
    printf '%s\t%s\n' \
      "$file" "$(shasum -a 256 "$ROOT/$file" | awk '{print $1}')"
  done | shasum -a 256 | awk '{print $1}'
)"
REMOTE_HARNESS_ROOT_REL=".cache/nvpn-release-mobile-join-harness/$REMOTE_HARNESS_DIGEST"
REMOTE_SCRIPT_REL="$REMOTE_HARNESS_ROOT_REL/scripts/macos-release-mobile-join-remote.sh"
RESULT_DIR="${NVPN_RELEASE_JOIN_RESULT_DIR:-$ROOT/artifacts/mobile-release-join}"
PRIVATE_DIR="$RESULT_DIR/.desktop-private-$$"
HOST_BUILD_ROOT="$PRIVATE_DIR/source"
HOST_FIPS_ROOT="$PRIVATE_DIR/fips"
HOST_APP="$HOST_BUILD_ROOT/dist/macos/Nostr VPN.app"
HOST_PACKAGE="$PRIVATE_DIR/package"
HOST_SUPPORT="$PRIVATE_DIR/support"
HOST_FIXTURE="$HOST_SUPPORT/fixtures/desktop_manual_join_e2e_fixture"
HOST_MANUAL_DRIVER="$HOST_SUPPORT/drivers/desktop-manual-join-ax"
HOST_SERVICE_DRIVER="$HOST_SUPPORT/drivers/macos-service-toggle-ax"
HOST_ARCHIVE="$PRIVATE_DIR/macos-release-gate.zip"
HOST_RECEIPT="$PRIVATE_DIR/artifact.json"
HOST_COMPONENT_PROOF="$PRIVATE_DIR/macos-component-proof.json"
PUBLICATION_DIR="$RESULT_DIR/macos/publication"
CACHED_APP="$PUBLICATION_DIR/Nostr VPN.app"
CACHED_RECEIPT="$PUBLICATION_DIR/artifact.json"
RUN_ONLY_RECEIPT="${NVPN_MACOS_RELEASE_RUN_ONLY_RECEIPT:-$RESULT_DIR/macos/artifact.json}"
RELEASE_JOIN_UI_WAIT_SECS="${NVPN_RELEASE_JOIN_UI_WAIT_SECS:-15}"
RELEASE_JOIN_DELIVERY_WAIT_SECS="${NVPN_RELEASE_JOIN_DELIVERY_WAIT_SECS:-15}"
RELEASE_JOIN_CAMERA_WAIT_SECS="${NVPN_RELEASE_JOIN_CAMERA_WAIT_SECS:-30}"
RELEASE_JOIN_IOS_SETUP_WAIT_SECS="${NVPN_RELEASE_JOIN_IOS_SETUP_WAIT_SECS:-90}"
for value in \
  "$RELEASE_JOIN_UI_WAIT_SECS" \
  "$RELEASE_JOIN_DELIVERY_WAIT_SECS" \
  "$RELEASE_JOIN_CAMERA_WAIT_SECS" \
  "$RELEASE_JOIN_IOS_SETUP_WAIT_SECS"
do
  [[ "$value" =~ ^[1-9][0-9]*$ ]] || {
    echo "Join gate timeouts must be positive integers" >&2
    exit 2
  }
done
((RELEASE_JOIN_DELIVERY_WAIT_SECS <= 15)) || {
  echo "Join delivery wait cannot exceed 15 seconds" >&2
  exit 2
}
((RELEASE_JOIN_IOS_SETUP_WAIT_SECS <= 90)) || {
  echo "iOS setup wait cannot exceed 90 seconds" >&2
  exit 2
}
mkdir -p "$PRIVATE_DIR" "$RESULT_DIR/macos"
chmod 700 "$PRIVATE_DIR"

export RESULT_DIR PRIVATE_DIR RELEASE_JOIN_UI_WAIT_SECS
export RELEASE_JOIN_DELIVERY_WAIT_SECS RELEASE_JOIN_CAMERA_WAIT_SECS
export RELEASE_JOIN_IOS_SETUP_WAIT_SECS
release_join_require_clean_fips
release_join_configure_install_modes
APP_GIT_SHA="$(git -C "$ROOT" rev-parse HEAD)"
APP_GIT_TREE="$(git -C "$ROOT" rev-parse HEAD^{tree})"
PRODUCT_GIT_SHA="$APP_GIT_SHA"
PRODUCT_GIT_TREE="$APP_GIT_TREE"
APP_SOURCE_DATE_EPOCH="$(git -C "$ROOT" log -1 --format=%ct HEAD)"
release_join_assert_app_unchanged "$APP_GIT_SHA" "$APP_GIT_TREE"

remote_pid=""
acceptance_observer_pids=()
remote_app_ownership_armed=0
remote_harness_install_attempted=0
cleanup() {
  local status=$?
  local cleanup_status=0
  trap - EXIT
  if [[ -n "${RELEASE_JOIN_IOS_TEST_PID:-}" ]] \
      && kill -0 "$RELEASE_JOIN_IOS_TEST_PID" 2>/dev/null
  then
    kill "$RELEASE_JOIN_IOS_TEST_PID" >/dev/null 2>&1 || true
    wait "$RELEASE_JOIN_IOS_TEST_PID" >/dev/null 2>&1 || true
  fi
  RELEASE_JOIN_IOS_TEST_PID=""
  local observer_pid
  for observer_pid in "${acceptance_observer_pids[@]-}"; do
    [[ -n "$observer_pid" ]] || continue
    kill "$observer_pid" >/dev/null 2>&1 || true
    wait "$observer_pid" >/dev/null 2>&1 || true
  done
  if [[ -n "$remote_pid" ]] \
    && ! macos_release_stop_owned_child "$remote_pid"
  then
    cleanup_status=1
    echo "macOS VM remote child survived bounded cleanup" >&2
    [[ "$status" -ne 0 ]] || status="$cleanup_status"
  fi
  remote_pid=""
  if [[ "$remote_app_ownership_armed" -eq 1 ]]; then
    if remote cleanup >/dev/null; then
      :
    else
      cleanup_status=$?
      echo "macOS VM app restoration failed during release gate cleanup (status $cleanup_status)" >&2
      [[ "$status" -ne 0 ]] || status="$cleanup_status"
    fi
  fi
  if [[ "$remote_harness_install_attempted" -eq 1 ]]; then
    if remove_remote_harness >/dev/null; then
      :
    else
      cleanup_status=$?
      echo "macOS VM external harness cache survived cleanup (status $cleanup_status)" >&2
      [[ "$status" -ne 0 ]] || status="$cleanup_status"
    fi
  fi
  if [[ "$status" -ne 0 && -s "$PRIVATE_DIR/android-ui.xml" ]]; then
    cp "$PRIVATE_DIR/android-ui.xml" \
      "$RESULT_DIR/macos/android-ui-failure.xml"
  fi
  rm -rf "$PRIVATE_DIR"
  exit "$status"
}
trap cleanup EXIT

remote() {
  local subcommand="$1"
  shift
  local remote_command argument
  # shellcheck disable=SC2016 # $HOME is expanded by the remote shell.
  printf -v remote_command \
    'cd %q && env NVPN_APP_REPO_PATH=. NVPN_FIPS_REPO_PATH=%q NVPN_MACOS_RELEASE_JOIN_ARTIFACT_DIR=%q NVPN_EXTERNAL_HARNESS_DIGEST=%q NVPN_EXPECTED_APP_GIT_SHA=%q NVPN_EXPECTED_APP_GIT_TREE=%q NVPN_EXPECTED_HARNESS_GIT_SHA=%q NVPN_EXPECTED_HARNESS_GIT_TREE=%q NVPN_EXPECTED_FIPS_GIT_SHA=%q NVPN_EXPECTED_FIPS_GIT_TREE=%q NVPN_EXPECTED_FIPS_VERSION=%q NVPN_EXPECTED_MACOS_SIGNING_IDENTITY_SHA1=%q NVPN_EXPECTED_MACOS_SIGNING_TEAM_ID=%q NVPN_EXPECTED_MACOS_SIGNER_CERT_SHA256=%q "$HOME"/%q %q' \
    "$GUEST_REPO" \
    "../fips" \
    "artifacts/macos-release-mobile-join" \
    "$REMOTE_HARNESS_DIGEST" \
    "$PRODUCT_GIT_SHA" \
    "$PRODUCT_GIT_TREE" \
    "$APP_GIT_SHA" \
    "$APP_GIT_TREE" \
    "$RELEASE_JOIN_FIPS_SHA" \
    "$RELEASE_JOIN_FIPS_TREE" \
    "$RELEASE_JOIN_FIPS_VERSION" \
    "$MACOS_SIGNING_IDENTITY" \
    "$EXPECTED_MACOS_TEAM" \
    "$EXPECTED_MACOS_CERT" \
    "$REMOTE_SCRIPT_REL" \
    "$subcommand"
  for argument in "$@"; do
    printf -v remote_command '%s %q' "$remote_command" "$argument"
  done
  ssh -o BatchMode=yes "$MAC_HOST" "$remote_command"
}

install_remote_harness() {
  local install_command
  # shellcheck disable=SC2016 # $HOME is expanded by the remote shell.
  printf -v install_command \
    'set -e; destination="$HOME"/%q; rm -rf "$destination"; mkdir -p "$destination"; tar -xf - -C "$destination"; chmod 700 "$destination/scripts/macos-release-mobile-join-remote.sh"' \
    "$REMOTE_HARNESS_ROOT_REL"
  tar -cf - -C "$ROOT" "${REMOTE_HARNESS_FILES[@]}" \
    | ssh -o BatchMode=yes "$MAC_HOST" "$install_command"
}

remove_remote_harness() {
  local remove_command
  # This exact content-addressed path contains only the transferred harness.
  # It deliberately does not invoke app/profile restoration.
  # shellcheck disable=SC2016 # $HOME is expanded by the remote shell.
  printf -v remove_command \
    'target="$HOME"/%q; rm -rf "$target"; test ! -e "$target"' \
    "$REMOTE_HARNESS_ROOT_REL"
  ssh -o BatchMode=yes "$MAC_HOST" "$remove_command"
}

wait_log_marker() {
  local log="$1" marker="$2" timeout="${3:-15}"
  local deadline
  deadline=$((SECONDS + timeout))
  while ((SECONDS < deadline)); do
    grep -Fq "NVPN_RELEASE_JOIN_MARKER $marker" "$log" 2>/dev/null && return 0
    if [[ -n "$remote_pid" ]] && ! kill -0 "$remote_pid" 2>/dev/null; then
      wait "$remote_pid" || true
      remote_pid=""
      tail -n 100 "$log" >&2 || true
      return 1
    fi
    sleep 0.25
  done
  echo "macOS join marker timed out after ${timeout}s: $marker" >&2
  tail -n 160 "$log" >&2 || true
  return 1
}

marker_value() {
  release_join_marker_value_from_log "$1" "$2"
}

macos_reverse_desktop_visible() {
  grep -Fq \
    "NVPN_RELEASE_JOIN_MARKER NVPN_RELEASE_JOIN_MANUAL_COMPLETE=$RELEASE_JOIN_ANDROID_ADMIN_ID" \
    "$1" 2>/dev/null \
    && release_join_now_ms
}

macos_admin_desktop_visible() {
  grep -Fq \
    "NVPN_RELEASE_JOIN_MARKER NVPN_RELEASE_JOIN_ADMIN_ACCEPTED=$RELEASE_JOIN_ANDROID_JOINER_ID" \
    "$1" 2>/dev/null \
    && release_join_now_ms
}

macos_reverse_pixel_visible() {
  release_join_android_accepted_snapshot_ms "$1"
}

macos_mobile_direction_cleanup() {
  local status=$? observer_pid
  trap - EXIT
  if [[ -n "${RELEASE_JOIN_IOS_TEST_PID:-}" ]] \
      && kill -0 "$RELEASE_JOIN_IOS_TEST_PID" 2>/dev/null
  then
    if [[ ! "${ios_test_pid_owner:-}" =~ ^[0-9]+$ ]] \
      || ! macos_release_stop_owned_child \
        "$RELEASE_JOIN_IOS_TEST_PID" "$ios_test_pid_owner"
    then
      status=1
      echo "iOS direction runner survived bounded cleanup" >&2
    fi
  fi
  RELEASE_JOIN_IOS_TEST_PID=""
  for observer_pid in "${acceptance_observer_pids[@]-}"; do
    [[ -n "$observer_pid" ]] || continue
    kill "$observer_pid" >/dev/null 2>&1 || true
    wait "$observer_pid" >/dev/null 2>&1 || true
  done
  if [[ -n "$remote_pid" ]]; then
    if [[ ! "${remote_pid_owner:-}" =~ ^[0-9]+$ ]] \
      || ! macos_release_stop_owned_child "$remote_pid" "$remote_pid_owner"
    then
      status=1
      echo "macOS VM direction child survived bounded cleanup" >&2
    fi
    remote_pid=""
  fi
  if [[ "$status" -ne 0 && -s "$PRIVATE_DIR/android-ui.xml" ]]; then
    cp "$PRIVATE_DIR/android-ui.xml" \
      "$RESULT_DIR/macos/${MACOS_MOBILE_DIRECTION_LABEL}-android-ui.xml"
  fi
  exit "$status"
}

macos_mobile_direction_child_owner() {
  local pid="$1" owner
  owner="$(ps -ww -p "$pid" -o ppid= 2>/dev/null | tr -d '[:space:]')"
  [[ "$owner" =~ ^[0-9]+$ ]] || {
    echo "macOS/mobile direction child has no stable owner" >&2
    return 1
  }
  printf '%s\n' "$owner"
}

prepare_macos_mobile_direction() {
  local label="$1"
  remote reset-profile \
    >"$RESULT_DIR/macos/$label-preclean.log" 2>&1
  remote service-preflight \
    >"$RESULT_DIR/macos/$label-service-preflight.log" 2>&1
}

finish_macos_mobile_direction() {
  local label="$1"
  remote reset-profile \
    >"$RESULT_DIR/macos/$label-cleanup.log" 2>&1
}

ios_log() {
  printf '%s/macos/%s.log\n' "$RESULT_DIR" "$1"
}

ios_marker_value_from() {
  marker_value "$1" "$2"
}

ios_create_admin() {
  local label="$1" log
  log="$(ios_log "$label-create-admin")"
  release_join_ios_run_test \
    testCreateAdminNetworkAndReportPublicValues "$log" \
    "NVPN_RELEASE_JOIN_NETWORK_NAME=$label"
  RELEASE_JOIN_IOS_ADMIN_ID="$(
    ios_marker_value_from "$log" NVPN_RELEASE_JOIN_ADMIN_ID
  )"
  RELEASE_JOIN_IOS_NETWORK_ID="$(
    ios_marker_value_from "$log" NVPN_RELEASE_JOIN_NETWORK_ID
  )"
  release_join_valid_npub "$RELEASE_JOIN_IOS_ADMIN_ID" \
    || { echo "iPhone Release UI did not report a valid admin identity" >&2; return 1; }
  [[ -n "$RELEASE_JOIN_IOS_NETWORK_ID" ]] || {
    echo "iPhone Release UI did not report a network identity" >&2
    return 1
  }
}

finish_remote() {
  local log="$1" status=0
  wait "$remote_pid" || status=$?
  remote_pid=""
  remote_pid_owner=""
  if [[ "$status" -ne 0 ]]; then
    tail -n 120 "$log" >&2 || true
  fi
  return "$status"
}

assert_delivery_deadline() {
  local submitted_ms="$1" completed_ms="$2" label="$3"
  [[ "$submitted_ms" =~ ^[0-9]+$ ]] || {
    echo "$label has no real approval timestamp" >&2
    return 1
  }
  local elapsed=$((completed_ms - submitted_ms))
  assert_delivery_duration "$elapsed" "$label"
}

assert_delivery_duration() {
  local elapsed="$1" label="$2"
  ((elapsed >= 0 && elapsed <= RELEASE_JOIN_DELIVERY_WAIT_SECS * 1000)) || {
    echo "$label took ${elapsed}ms after approval" >&2
    return 1
  }
  printf '%s\t%s\n' "$label" "$elapsed" \
    >>"$RESULT_DIR/macos/delivery-times.tsv"
}

read_cached_identity() {
  local extra
  IFS=$'\t' read -r CACHE_PRODUCT_SHA CACHE_PRODUCT_TREE \
    CACHE_FIPS_SHA CACHE_FIPS_TREE CACHE_FIPS_VERSION \
    CACHE_HARNESS_SHA CACHE_HARNESS_TREE extra <<<"$(
      python3 -c '
import json,sys
v=json.load(open(sys.argv[1])); p=v.get("componentInputProof") or {}
keys=("appGitSha","appGitTree","fipsGitSha","fipsGitTree","fipsCoreVersion")
print(*(v.get(key, "") for key in keys), p.get("candidate_app_git_sha", ""), p.get("candidate_app_git_tree", ""), sep="\t")
' "$1"
    )"
  [[ "$CACHE_PRODUCT_SHA" =~ ^[0-9a-f]{40}$ \
    && "$CACHE_PRODUCT_TREE" =~ ^[0-9a-f]{40}$ \
    && "$CACHE_FIPS_SHA" =~ ^[0-9a-f]{40}$ \
    && "$CACHE_FIPS_TREE" =~ ^[0-9a-f]{40}$ \
    && -n "$CACHE_FIPS_VERSION" \
    && "$CACHE_HARNESS_SHA" =~ ^[0-9a-f]{40}$ \
    && "$CACHE_HARNESS_TREE" =~ ^[0-9a-f]{40}$ \
    && -z "${extra:-}" ]] || {
    echo "Cached macOS Release receipt has no exact component identity" >&2
    return 1
  }
}

select_run_only_artifact() {
  local expected_sha="${NVPN_MACOS_RELEASE_RUN_ONLY_HARNESS_GIT_SHA:-}"
  local expected_tree="${NVPN_MACOS_RELEASE_RUN_ONLY_HARNESS_GIT_TREE:-}"
  [[ -s "$RUN_ONLY_RECEIPT" \
    && "$expected_sha" =~ ^[0-9a-f]{40}$ \
    && "$expected_tree" =~ ^[0-9a-f]{40}$ ]] || {
    echo "macOS run-only requires an explicit cached receipt and exact frozen artifact-harness pins" >&2
    return 1
  }
  read_cached_identity "$RUN_ONLY_RECEIPT"
  [[ "$CACHE_HARNESS_SHA" == "$expected_sha" \
    && "$CACHE_HARNESS_TREE" == "$expected_tree" \
    && "$CACHE_FIPS_SHA" == "$RELEASE_JOIN_FIPS_SHA" \
    && "$CACHE_FIPS_TREE" == "$RELEASE_JOIN_FIPS_TREE" \
    && "$CACHE_FIPS_VERSION" == "$RELEASE_JOIN_FIPS_VERSION" ]] || {
    echo "Cached macOS artifact differs from frozen run-only pins" >&2
    return 1
  }
  PRODUCT_GIT_SHA="$CACHE_PRODUCT_SHA"
  PRODUCT_GIT_TREE="$CACHE_PRODUCT_TREE"
  APP_GIT_SHA="$CACHE_HARNESS_SHA"
  APP_GIT_TREE="$CACHE_HARNESS_TREE"
  if [[ "$RUN_ONLY_RECEIPT" != "$RESULT_DIR/macos/artifact.json" ]]; then
    cp "$RUN_ONLY_RECEIPT" "$RESULT_DIR/macos/artifact.json"
  fi
}

verify_run_only_receipt_binding() {
  [[ "$ARTIFACT_ACTION" == "run-only" ]] || return 0
  local host_receipt_sha remote_receipt_sha
  host_receipt_sha="$(
    shasum -a 256 "$RESULT_DIR/macos/artifact.json" | awk '{print $1}'
  )"
  remote_receipt_sha="$(
    python3 -c '
import json,sys
print(json.load(open(sys.argv[1])).get("artifactReceiptSha256", ""))
' "$RESULT_DIR/macos/verification.json"
  )"
  [[ "$remote_receipt_sha" =~ ^[0-9a-f]{64}$ \
    && "$host_receipt_sha" == "$remote_receipt_sha" ]] || {
    echo "Remote macOS verification does not bind the selected run-only receipt" >&2
    return 1
  }
}

write_component_proof() {
  node --input-type=module - \
    "$ROOT" "$1" "$2" "$APP_GIT_SHA" "$APP_GIT_TREE" <<'JS'
import { pathToFileURL } from 'node:url'
const [root, receiptCommit, receiptTree, candidateCommit, candidateTree] = process.argv.slice(2)
const source = await import(pathToFileURL(`${root}/scripts/release-component-source.mjs`))
console.log(JSON.stringify(source.proveUnchangedPlatformInputs({
  candidateRoot: root, platform: 'macos', receiptCommit, receiptTree,
  candidateCommit, candidateTree,
})))
JS
}

prepare_host_artifact() {
  local build_log="$RESULT_DIR/macos/host-build.log"
  local reuse_app=0 support
  rm -rf "$HOST_PACKAGE" "$HOST_SUPPORT"
  rm -f "$HOST_ARCHIVE" "$HOST_RECEIPT"
  : >"$build_log"
  if [[ -d "$CACHED_APP" || -f "$CACHED_RECEIPT" ]]; then
    [[ -d "$CACHED_APP" && -f "$CACHED_RECEIPT" ]] || {
      echo "Cached macOS Release app/receipt pair is incomplete" >&2
      return 1
    }
  fi
  if [[ -d "$CACHED_APP" ]]; then
    read_cached_identity "$CACHED_RECEIPT"
    if [[ "$CACHE_FIPS_SHA" == "$RELEASE_JOIN_FIPS_SHA" \
      && "$CACHE_FIPS_TREE" == "$RELEASE_JOIN_FIPS_TREE" \
      && "$CACHE_FIPS_VERSION" == "$RELEASE_JOIN_FIPS_VERSION" ]] \
      && write_component_proof "$CACHE_PRODUCT_SHA" "$CACHE_PRODUCT_TREE" \
        >"$HOST_COMPONENT_PROOF" 2>>"$build_log"
    then
      PRODUCT_GIT_SHA="$CACHE_PRODUCT_SHA"
      PRODUCT_GIT_TREE="$CACHE_PRODUCT_TREE"
      reuse_app=1
    fi
  fi
  if ((reuse_app)); then
    python3 "$ROOT/scripts/macos_release_join_artifact.py" validate-published-app \
      --receipt "$CACHED_RECEIPT" \
      --app "$CACHED_APP" \
      --expected-app-head "$PRODUCT_GIT_SHA" \
      --expected-app-tree "$PRODUCT_GIT_TREE" \
      --expected-team "$EXPECTED_MACOS_TEAM" \
      --expected-identity-sha1 "$MACOS_SIGNING_IDENTITY" \
      --expected-signer-sha256 "$EXPECTED_MACOS_CERT" \
      --require-gate-bundle-tree \
      >"$RESULT_DIR/macos/host-app-reuse.json"
    mkdir -p "$(dirname "$HOST_APP")"
    ditto "$CACHED_APP" "$HOST_APP"
  else
    PRODUCT_GIT_SHA="$APP_GIT_SHA"
    PRODUCT_GIT_TREE="$APP_GIT_TREE"
    write_component_proof "$PRODUCT_GIT_SHA" "$PRODUCT_GIT_TREE" \
      >"$HOST_COMPONENT_PROOF"
  fi
  if ((!reuse_app)) && ! (
    cd "$HOST_BUILD_ROOT"
    MACOS_SIGNING_IDENTITY="$MACOS_SIGNING_IDENTITY" \
      NVPN_BUILD_GIT_SHA="$APP_GIT_SHA" \
      SOURCE_DATE_EPOCH="$APP_SOURCE_DATE_EPOCH" \
      NVPN_FIPS_REPO_PATH="$HOST_FIPS_ROOT" \
      NVPN_MACOS_RUST_PROFILE="$MACOS_RUST_PROFILE" \
      NVPN_MACOS_XCODE_CONFIGURATION="$MACOS_XCODE_CONFIGURATION" \
      NVPN_MACOS_RUST_TARGETS=aarch64-apple-darwin \
      NVPN_MACOS_REQUIRE_SIGNING=1 \
      "$HOST_BUILD_ROOT/scripts/macos-build" macos-app
  ) >>"$build_log" 2>&1
  then
    tail -n 120 "$build_log" >&2 || true
    return 1
  fi
  if ! (
    cd "$HOST_BUILD_ROOT"
    NVPN_FIPS_REPO_PATH="$HOST_FIPS_ROOT" \
      SOURCE_DATE_EPOCH="$APP_SOURCE_DATE_EPOCH" \
      NVPN_MACOS_HOST_TARGET=aarch64-apple-darwin \
      NVPN_MACOS_GATE_SUPPORT_DIR="$HOST_SUPPORT" \
      "$HOST_BUILD_ROOT/scripts/macos-build" macos-gate-support
  ) >>"$build_log" 2>&1
  then
    tail -n 120 "$build_log" >&2 || true
    return 1
  fi
  [[ "$(git -C "$HOST_FIPS_ROOT" rev-parse HEAD)" == "$RELEASE_JOIN_FIPS_SHA" \
    && "$(git -C "$HOST_FIPS_ROOT" rev-parse HEAD^{tree})" == "$RELEASE_JOIN_FIPS_TREE" \
    && -z "$(git -C "$HOST_FIPS_ROOT" status --porcelain --untracked-files=all)" ]] || {
    echo "Isolated FIPS source changed while building Release join artifacts" >&2
    return 1
  }
  release_join_assert_app_unchanged "$APP_GIT_SHA" "$APP_GIT_TREE"
  codesign --verify --deep --strict "$HOST_APP"
  for support in \
    "$HOST_FIXTURE" \
    "$HOST_MANUAL_DRIVER" \
    "$HOST_SERVICE_DRIVER"
  do
    [[ -x "$support" ]] || {
      echo "Host-built macOS Release gate support is missing: $support" >&2
      return 1
    }
    codesign --force --timestamp --options runtime \
      --sign "$MACOS_SIGNING_IDENTITY" "$support"
    codesign --verify --strict "$support"
  done

  mkdir -p "$HOST_PACKAGE/fixtures" "$HOST_PACKAGE/drivers"
  cp "$HOST_COMPONENT_PROOF" "$HOST_PACKAGE/component-proof.json"
  ditto "$HOST_APP" "$HOST_PACKAGE/Nostr VPN.app"
  ditto "$HOST_FIXTURE" \
    "$HOST_PACKAGE/fixtures/desktop_manual_join_e2e_fixture"
  ditto "$HOST_MANUAL_DRIVER" \
    "$HOST_PACKAGE/drivers/desktop-manual-join-ax"
  ditto "$HOST_SERVICE_DRIVER" \
    "$HOST_PACKAGE/drivers/macos-service-toggle-ax"
  ditto -c -k --sequesterRsrc --keepParent \
    "$HOST_PACKAGE" "$HOST_ARCHIVE"
  python3 "$ROOT/scripts/macos_release_join_artifact.py" create \
    --receipt "$HOST_RECEIPT" \
    --package "$HOST_PACKAGE" \
    --app "$HOST_PACKAGE/Nostr VPN.app" \
    --archive "$HOST_ARCHIVE" \
    --manual-join-fixture \
      "$HOST_PACKAGE/fixtures/desktop_manual_join_e2e_fixture" \
    --manual-join-driver \
      "$HOST_PACKAGE/drivers/desktop-manual-join-ax" \
    --service-toggle-driver \
      "$HOST_PACKAGE/drivers/macos-service-toggle-ax" \
    --component-proof "$HOST_PACKAGE/component-proof.json" \
    --app-root "$ROOT" \
    --fips-root "$HOST_FIPS_ROOT" \
    --expected-app-head "$PRODUCT_GIT_SHA" \
    --expected-app-tree "$PRODUCT_GIT_TREE" \
    --expected-harness-head "$APP_GIT_SHA" \
    --expected-harness-tree "$APP_GIT_TREE" \
    --expected-fips-head "$RELEASE_JOIN_FIPS_SHA" \
    --expected-fips-tree "$RELEASE_JOIN_FIPS_TREE" \
    --expected-fips-version "$RELEASE_JOIN_FIPS_VERSION" \
    --expected-team "$EXPECTED_MACOS_TEAM" \
    --expected-identity-sha1 "$MACOS_SIGNING_IDENTITY" \
    --expected-signer-sha256 "$EXPECTED_MACOS_CERT"
}

prepare_host_sources() {
  rm -rf "$HOST_BUILD_ROOT" "$HOST_FIPS_ROOT"
  mkdir -p "$HOST_BUILD_ROOT"
  git -C "$ROOT" archive --format=tar "$APP_GIT_SHA" \
    | tar -x -C "$HOST_BUILD_ROOT"
  git clone --quiet --no-checkout --no-hardlinks \
    "$NVPN_FIPS_REPO_PATH" "$HOST_FIPS_ROOT"
  git -C "$HOST_FIPS_ROOT" checkout --quiet --detach "$RELEASE_JOIN_FIPS_SHA"
  [[ "$(git -C "$HOST_FIPS_ROOT" rev-parse HEAD)" == "$RELEASE_JOIN_FIPS_SHA" \
    && "$(git -C "$HOST_FIPS_ROOT" rev-parse HEAD^{tree})" == "$RELEASE_JOIN_FIPS_TREE" \
    && -z "$(git -C "$HOST_FIPS_ROOT" status --porcelain --untracked-files=all)" ]] || {
    echo "Could not isolate exact FIPS source for macOS Release artifacts" >&2
    return 1
  }
}

if [[ "$ARTIFACT_ACTION" == "full" || "$ARTIFACT_ACTION" == "run-only" ]]; then
  [[ "$MACOS_MOBILE_DIRECTIONS" == "pixel" || -n "${IOS_DEVICE:-}" ]] || {
    echo "macOS/mobile Release join gate requires IOS_DEVICE" >&2
    exit 2
  }
  release_join_reuse_artifacts || {
    echo "macOS/mobile Release join gate requires exact artifact reuse" >&2
    exit 2
  }
  if [[ "$MACOS_MOBILE_DIRECTIONS" == "all" ]]; then
    release_join_validate_reused_artifacts || {
      echo "macOS/mobile Release join gate rejected the exact mobile artifacts" >&2
      exit 1
    }
  else
    release_join_validate_reused_android_only || {
      echo "macOS/Pixel join gate rejected the exact Android artifact" >&2
      exit 1
    }
  fi
  ANDROID_ARTIFACT_RECEIPT="${NVPN_RELEASE_JOIN_ANDROID_RECEIPT:-}"
  ANDROID_INSTALL_RECEIPT="${NVPN_RELEASE_JOIN_ANDROID_INSTALL_RECEIPT:-$RESULT_DIR/android-release-install.json}"
  [[ -s "$ANDROID_ARTIFACT_RECEIPT" \
    && -s "$ANDROID_INSTALL_RECEIPT" ]] || {
    echo "macOS/mobile Release join gate requires the exact Android artifact and install receipts" >&2
    exit 1
  }
  android_install_validation=()
  [[ "$RELEASE_JOIN_INSTALL_ANDROID" -eq 1 ]] \
    || android_install_validation+=(--allow-verified-no-install)
  python3 "$ROOT/scripts/desktop_mobile_manual_join_receipt.py" \
    validate-android \
    --receipt "$ANDROID_INSTALL_RECEIPT" \
    --android-artifact-receipt "$ANDROID_ARTIFACT_RECEIPT" \
    --android-fips-metadata-receipt \
      "${NVPN_RELEASE_JOIN_ANDROID_FIPS_METADATA_RECEIPT:?exact Android FIPS receipt is required}" \
    --apk "$RELEASE_JOIN_ANDROID_APK" \
    --expected-android-app-sha "$RELEASE_JOIN_ANDROID_APP_SHA" \
    --expected-android-app-tree "$RELEASE_JOIN_ANDROID_APP_TREE" \
    --expected-android-fips-sha "$RELEASE_JOIN_FIPS_SHA" \
    --expected-android-fips-tree "$RELEASE_JOIN_FIPS_TREE" \
    --expected-android-fips-version "$RELEASE_JOIN_FIPS_VERSION" \
    ${android_install_validation[@]+"${android_install_validation[@]}"} \
    >/dev/null
fi

if [[ "$ARTIFACT_ACTION" != "verify-only" \
  && "$ARTIFACT_ACTION" != "run-only" ]]; then
  prepare_host_sources
fi
SYNC_FIPS_ROOT="$NVPN_FIPS_REPO_PATH"
if [[ "$ARTIFACT_ACTION" != "verify-only" \
  && "$ARTIFACT_ACTION" != "run-only" ]]; then
  SYNC_FIPS_ROOT="$HOST_FIPS_ROOT"
fi

if [[ "$ARTIFACT_ACTION" != "run-only" ]]; then
  case "${NVPN_MACOS_SKIP_GIT_SYNC:-0}" in
    1|true|TRUE|True|yes|YES|Yes|on|ON|On) ;;
    *)
      NVPN_MACOS_SYNC_PATH_DEPS=1 \
        NVPN_FIPS_REPO_PATH="$SYNC_FIPS_ROOT" \
        "$ROOT/scripts/macos-vm-git-sync.sh" "$MAC_HOST"
      ;;
  esac
fi

remote_harness_install_attempted=1
install_remote_harness

case "$ARTIFACT_ACTION" in
  verify-only)
    read_cached_identity "$RESULT_DIR/macos/artifact.json"
    PRODUCT_GIT_SHA="$CACHE_PRODUCT_SHA"
    PRODUCT_GIT_TREE="$CACHE_PRODUCT_TREE"
    remote verify-import | tee "$RESULT_DIR/macos/verify-import.log"
    ;;
  run-only)
    select_run_only_artifact
    remote verify-import | tee "$RESULT_DIR/macos/verify-import.log"
    ;;
  full|prepare-only)
    prepare_host_artifact
    remote stage
    scp -q "$HOST_ARCHIVE" "$HOST_RECEIPT" \
      "$MAC_HOST:$GUEST_REPO/artifacts/macos-release-mobile-join/"
    remote prepare | tee "$RESULT_DIR/macos/prepare.log"
    cp "$HOST_RECEIPT" "$RESULT_DIR/macos/artifact.json"
    rm -rf "$PUBLICATION_DIR"
    mkdir -p "$PUBLICATION_DIR"
    ditto "$HOST_APP" "$PUBLICATION_DIR/Nostr VPN.app"
    cp "$HOST_RECEIPT" "$PUBLICATION_DIR/artifact.json"
    ;;
esac
scp -q \
  "$MAC_HOST:$GUEST_REPO/artifacts/macos-release-mobile-join/verification.json" \
  "$RESULT_DIR/macos/verification.json"
verify_run_only_receipt_binding

if [[ "$ARTIFACT_ACTION" != "full" && "$ARTIFACT_ACTION" != "run-only" ]]; then
  echo "MACOS_VM_IMPORTED_RELEASE_ARTIFACT_OK"
  exit 0
fi

remote_app_ownership_armed=1

ANDROID_REQUESTED="${NVPN_ANDROID_SERIAL:-${ANDROID_SERIAL:-}}"
[[ -n "$ANDROID_REQUESTED" ]] || {
  echo "Set NVPN_ANDROID_SERIAL to the exact physical Android phone" >&2
  exit 2
}
ANDROID_SERIAL_SELECTED="$(
  select_physical_android_serial \
    "${ADB_BIN:-adb}" \
    "$ANDROID_REQUESTED"
)"
ADB=("${ADB_BIN:-adb}" -s "$ANDROID_SERIAL_SELECTED")
release_join_assert_one_android_package || {
  echo "macOS/mobile Release join gate requires the prepared Android app" >&2
  exit 1
}
RELEASE_JOIN_DEVICE_MUTATION_ALLOWED=1
export RELEASE_JOIN_DEVICE_MUTATION_ALLOWED
rm -f "$RESULT_DIR/macos/delivery-times.tsv"
macos_admin_android_status=0
android_admin_macos_status=0
macos_admin_ios_status=0
ios_admin_macos_status=0
DESKTOP_ADMIN_IPHONE_JOINER_RELAUNCH_DURABLE=0
IPHONE_ADMIN_DESKTOP_JOINER_RELAUNCH_DURABLE=0

# macOS admin -> physical Android joiner.
set +e
(
set -euo pipefail
MACOS_MOBILE_DIRECTION_LABEL=macos-admin-pixel-joiner
remote_pid=""
remote_pid_owner=""
ios_test_pid_owner=""
acceptance_observer_pids=()
trap macos_mobile_direction_cleanup EXIT
prepare_macos_mobile_direction "$MACOS_MOBILE_DIRECTION_LABEL"
release_join_reset_android_state
desktop_admin_log="$RESULT_DIR/macos/desktop-admin.log"
remote create-admin "ReleaseDesktopAdmin" >"$desktop_admin_log" 2>&1
DESKTOP_ADMIN_ID="$(marker_value "$desktop_admin_log" NVPN_RELEASE_JOIN_ADMIN_ID)"
DESKTOP_NETWORK_ID="$(marker_value "$desktop_admin_log" NVPN_RELEASE_JOIN_NETWORK_ID)"
release_join_valid_npub "$DESKTOP_ADMIN_ID"
[[ -n "$DESKTOP_NETWORK_ID" ]]
release_join_android_manual_submit "$DESKTOP_ADMIN_ID" "$DESKTOP_NETWORK_ID" \
  >"$RESULT_DIR/macos/android-manual-submit.log" 2>&1
desktop_add_log="$RESULT_DIR/macos/desktop-add-android.log"
desktop_android_log_offset="$(remote daemon-log-offset)"
remote admin-add "$RELEASE_JOIN_ANDROID_JOINER_ID" ReleaseGatePhone \
  >"$desktop_add_log" 2>&1 &
remote_pid=$!
remote_pid_owner="$(macos_mobile_direction_child_owner "$remote_pid")"
wait_log_marker "$desktop_add_log" NVPN_RELEASE_JOIN_APPROVAL_SUBMITTED_MS= 10
desktop_submitted_ms="$(release_join_now_ms)"
deadline=$((desktop_submitted_ms + RELEASE_JOIN_DELIVERY_WAIT_SECS * 1000))
desktop_file="$RESULT_DIR/macos/desktop-admin-desktop-detected-ms.txt"
pixel_file="$RESULT_DIR/macos/desktop-admin-pixel-detected-ms.txt"
rm -f "$desktop_file" "$pixel_file"
release_join_observe_pair_until_ms \
  "$deadline" \
  "$desktop_file" "macOS admin acceptance query" \
  macos_admin_desktop_visible "$desktop_add_log" \
  "$pixel_file" "Pixel acceptance query" \
  macos_reverse_pixel_visible "$DESKTOP_ADMIN_ID"
desktop_accepted="$(<"$desktop_file")"
pixel_accepted="$(<"$pixel_file")"
wait_log_marker "$desktop_add_log" NVPN_MACOS_RELEASE_APP_HOLDING=1
release_join_android_relaunch_and_wait_accepted "$DESKTOP_ADMIN_ID"
remote require-delivery-log \
  "$RELEASE_JOIN_ANDROID_JOINER_ID" "$desktop_android_log_offset" \
  >"$RESULT_DIR/macos/desktop-add-android-delivery.txt" \
  2>"$RESULT_DIR/macos/desktop-add-android-daemon.log"
((pixel_accepted > desktop_accepted)) \
  && desktop_accepted="$pixel_accepted"
assert_delivery_deadline \
  "$desktop_submitted_ms" "$desktop_accepted" \
  "macOS-admin-to-Android-manual"
wait "$remote_pid"
remote_pid=""
remote_pid_owner=""
remote verify "$RELEASE_JOIN_ANDROID_JOINER_ID" \
  >"$RESULT_DIR/macos/desktop-admin-verify.log"
)
macos_admin_android_status=$?
set -e
if ((macos_admin_android_status != 0)); then
  echo "macOS admin -> Pixel joiner failed; continuing reverse direction" >&2
fi
finish_macos_mobile_direction macos-admin-pixel-joiner

# Physical Android admin -> macOS joiner. The remote app remains alive while
# waiting for the exact Android admin row, so receipt delivery is real.
set +e
(
set -euo pipefail
MACOS_MOBILE_DIRECTION_LABEL=pixel-admin-macos-joiner
remote_pid=""
remote_pid_owner=""
ios_test_pid_owner=""
acceptance_observer_pids=()
trap macos_mobile_direction_cleanup EXIT
prepare_macos_mobile_direction "$MACOS_MOBILE_DIRECTION_LABEL"
release_join_reset_android_state
release_join_android_create_admin
desktop_joiner_identity_log="$RESULT_DIR/macos/android-admin-desktop-identity.log"
remote joiner-id >"$desktop_joiner_identity_log"
DESKTOP_JOINER_ID="$(
  marker_value "$desktop_joiner_identity_log" NVPN_RELEASE_JOIN_JOINER_ID
)"
release_join_valid_npub "$DESKTOP_JOINER_ID"
release_join_android_manual_admin_prepare "$DESKTOP_JOINER_ID" \
  >"$RESULT_DIR/macos/android-admin-prepare.log" 2>&1
desktop_join_log="$RESULT_DIR/macos/android-admin-desktop-join.log"
remote manual-join \
  "$RELEASE_JOIN_ANDROID_ADMIN_ID" "$RELEASE_JOIN_ANDROID_NETWORK_ID" \
  >"$desktop_join_log" 2>&1 &
remote_pid=$!
remote_pid_owner="$(macos_mobile_direction_child_owner "$remote_pid")"
wait_log_marker "$desktop_join_log" NVPN_RELEASE_JOIN_JOINER_ID= 10
[[ "$(marker_value "$desktop_join_log" NVPN_RELEASE_JOIN_JOINER_ID)" \
  == "$DESKTOP_JOINER_ID" ]] || {
  echo "macOS manual join used a different identity than preflight" >&2
  exit 1
}
wait_log_marker "$desktop_join_log" NVPN_RELEASE_JOIN_MANUAL_SUBMITTED=1 10
android_admin_log="$RESULT_DIR/macos/android-admin-add-desktop.log"
release_join_android_manual_admin_tap "$DESKTOP_JOINER_ID" \
  | tee "$android_admin_log"
android_submitted_ms="$(
  sed -n 's/.*NVPN_RELEASE_JOIN_APPROVAL_SUBMITTED_MS=//p' \
    "$android_admin_log" | tail -n 1
)"
deadline=$((android_submitted_ms + RELEASE_JOIN_DELIVERY_WAIT_SECS * 1000))
desktop_file="$RESULT_DIR/macos/android-admin-desktop-detected-ms.txt"
pixel_file="$RESULT_DIR/macos/android-admin-pixel-detected-ms.txt"
rm -f "$desktop_file" "$pixel_file"
release_join_observe_pair_until_ms \
  "$deadline" \
  "$desktop_file" "macOS reverse acceptance query" \
  macos_reverse_desktop_visible "$desktop_join_log" \
  "$pixel_file" "Pixel reverse acceptance query" \
  macos_reverse_pixel_visible "$DESKTOP_JOINER_ID"
macos_accepted="$(<"$desktop_file")"
pixel_accepted="$(<"$pixel_file")"
finish_remote "$desktop_join_log"
remote verify "$RELEASE_JOIN_ANDROID_ADMIN_ID" \
  >"$RESULT_DIR/macos/desktop-joiner-verify.log"
android_completed_ms="$macos_accepted"
((pixel_accepted > macos_accepted)) \
  && android_completed_ms="$pixel_accepted"
assert_delivery_deadline \
  "$android_submitted_ms" "$android_completed_ms" \
  "Android-admin-to-macOS-manual"
release_join_android_relaunch_and_wait_accepted "$DESKTOP_JOINER_ID"
)
android_admin_macos_status=$?
set -e
if ((android_admin_macos_status != 0)); then
  echo "Pixel admin -> macOS joiner failed; continuing independent Apple checks" >&2
fi
finish_macos_mobile_direction pixel-admin-macos-joiner

if [[ "$MACOS_MOBILE_DIRECTIONS" == "all" ]]; then
# macOS admin -> physical iPhone joiner. XCTest only drives the shipped
# accessibility tree; the app receives no launch arguments or environment.
set +e
(
set -euo pipefail
MACOS_MOBILE_DIRECTION_LABEL=macos-admin-iphone-joiner
remote_pid=""
remote_pid_owner=""
ios_test_pid_owner=""
acceptance_observer_pids=()
trap macos_mobile_direction_cleanup EXIT
prepare_macos_mobile_direction "$MACOS_MOBILE_DIRECTION_LABEL"
release_join_restart_ios_in_place
desktop_ios_admin_log="$RESULT_DIR/macos/desktop-ios-admin.log"
remote create-admin "ReleaseMacIphoneAdmin" >"$desktop_ios_admin_log" 2>&1
DESKTOP_IOS_ADMIN_ID="$(
  marker_value "$desktop_ios_admin_log" NVPN_RELEASE_JOIN_ADMIN_ID
)"
DESKTOP_IOS_NETWORK_ID="$(
  marker_value "$desktop_ios_admin_log" NVPN_RELEASE_JOIN_NETWORK_ID
)"
release_join_valid_npub "$DESKTOP_IOS_ADMIN_ID"
[[ -n "$DESKTOP_IOS_NETWORK_ID" ]]
ios_join_log="$(ios_log macos-admin-iphone-join)"
release_join_ios_start_test \
  testManualJoinAndRequireRosterCompletion "$ios_join_log" \
  "NVPN_RELEASE_JOIN_ADMIN_ID=$DESKTOP_IOS_ADMIN_ID" \
  "NVPN_RELEASE_JOIN_NETWORK_ID=$DESKTOP_IOS_NETWORK_ID"
ios_test_pid_owner="$(
  macos_mobile_direction_child_owner "$RELEASE_JOIN_IOS_TEST_PID"
)"
release_join_ios_wait_marker \
  NVPN_RELEASE_JOIN_JOINER_ID= "$RELEASE_JOIN_IOS_SETUP_WAIT_SECS" \
  || { echo "iPhone manual join did not expose its public identity" >&2; exit 1; }
IOS_JOINER_ID="$(
  ios_marker_value_from "$ios_join_log" NVPN_RELEASE_JOIN_JOINER_ID
)"
release_join_valid_npub "$IOS_JOINER_ID"
release_join_ios_wait_marker \
  NVPN_RELEASE_JOIN_MANUAL_SUBMITTED=1 "$RELEASE_JOIN_IOS_SETUP_WAIT_SECS" \
  || { echo "iPhone did not submit through shipped manual-join controls" >&2; exit 1; }
desktop_add_ios_log="$RESULT_DIR/macos/desktop-add-iphone.log"
desktop_iphone_log_offset="$(remote daemon-log-offset)"
remote admin-add "$IOS_JOINER_ID" ReleaseGateIphone \
  >"$desktop_add_ios_log" 2>&1 &
remote_pid=$!
remote_pid_owner="$(macos_mobile_direction_child_owner "$remote_pid")"
wait_log_marker \
  "$desktop_add_ios_log" NVPN_RELEASE_JOIN_APPROVAL_SUBMITTED_MS= 10
desktop_ios_submitted_ms="$(release_join_now_ms)"
release_join_ios_wait_marker \
  NVPN_RELEASE_JOIN_ROSTER_APPLIED_MS= "$RELEASE_JOIN_DELIVERY_WAIT_SECS" \
  || {
    echo "iPhone did not receive the macOS signed roster in time" >&2
    exit 1
  }
desktop_ios_completed_ms="$(release_join_now_ms)"
assert_delivery_deadline \
  "$desktop_ios_submitted_ms" "$desktop_ios_completed_ms" \
  "macOS-admin-to-iPhone-manual"
wait_log_marker \
  "$desktop_add_ios_log" "NVPN_RELEASE_JOIN_ADMIN_ACCEPTED=$IOS_JOINER_ID"
wait_log_marker "$desktop_add_ios_log" NVPN_MACOS_RELEASE_APP_HOLDING=1
release_join_ios_finish_test \
  || {
    echo "iPhone did not receive and retain the macOS signed roster" >&2
    exit 1
  }
iphone_joiner_relaunch_admin="$(
  ios_marker_value_from \
    "$ios_join_log" NVPN_RELEASE_JOIN_RELAUNCH_DURABLE
)"
[[ "$iphone_joiner_relaunch_admin" == "$DESKTOP_IOS_ADMIN_ID" ]] \
  || {
    echo "iPhone relaunch evidence did not name the exact macOS admin" >&2
    exit 1
  }
DESKTOP_ADMIN_IPHONE_JOINER_RELAUNCH_DURABLE=1
remote require-delivery-log \
  "$IOS_JOINER_ID" "$desktop_iphone_log_offset" \
  >"$RESULT_DIR/macos/desktop-add-iphone-delivery.txt" \
  2>"$RESULT_DIR/macos/desktop-add-iphone-daemon.log"
wait "$remote_pid"
remote_pid=""
remote_pid_owner=""
remote verify "$IOS_JOINER_ID" \
  >"$RESULT_DIR/macos/desktop-ios-admin-verify.log"
)
macos_admin_ios_status=$?
set -e
if ((macos_admin_ios_status != 0)); then
  echo "macOS admin -> iPhone joiner failed; continuing reverse direction" >&2
else
  DESKTOP_ADMIN_IPHONE_JOINER_RELAUNCH_DURABLE=1
fi
finish_macos_mobile_direction macos-admin-iphone-joiner

# Physical iPhone admin -> macOS joiner.
set +e
(
set -euo pipefail
MACOS_MOBILE_DIRECTION_LABEL=iphone-admin-macos-joiner
remote_pid=""
remote_pid_owner=""
ios_test_pid_owner=""
acceptance_observer_pids=()
trap macos_mobile_direction_cleanup EXIT
prepare_macos_mobile_direction "$MACOS_MOBILE_DIRECTION_LABEL"
release_join_restart_ios_in_place
ios_create_admin "Release iPhone macOS admin"
desktop_ios_join_log="$RESULT_DIR/macos/iphone-admin-desktop-join.log"
remote manual-join \
  "$RELEASE_JOIN_IOS_ADMIN_ID" "$RELEASE_JOIN_IOS_NETWORK_ID" \
  >"$desktop_ios_join_log" 2>&1 &
remote_pid=$!
remote_pid_owner="$(macos_mobile_direction_child_owner "$remote_pid")"
wait_log_marker "$desktop_ios_join_log" NVPN_RELEASE_JOIN_JOINER_ID= 10
DESKTOP_IOS_JOINER_ID="$(
  marker_value "$desktop_ios_join_log" NVPN_RELEASE_JOIN_JOINER_ID
)"
release_join_valid_npub "$DESKTOP_IOS_JOINER_ID"
wait_log_marker "$desktop_ios_join_log" NVPN_RELEASE_JOIN_MANUAL_SUBMITTED=1 10
if grep -Fq "NVPN_RELEASE_JOIN_MARKER NVPN_RELEASE_JOIN_MANUAL_COMPLETE_MS=" \
  "$desktop_ios_join_log"
then
  echo "macOS joiner completed before the iPhone approval" >&2
  exit 1
fi
ios_admin_log="$(ios_log iphone-admin-macos-add)"
release_join_ios_start_test \
  testManualAdminAddRequiresRosterProgress "$ios_admin_log" \
  "NVPN_RELEASE_JOIN_JOINER_ID=$DESKTOP_IOS_JOINER_ID"
ios_test_pid_owner="$(
  macos_mobile_direction_child_owner "$RELEASE_JOIN_IOS_TEST_PID"
)"
release_join_ios_wait_marker \
  NVPN_RELEASE_JOIN_APPROVAL_SUBMITTED_MS= "$RELEASE_JOIN_IOS_SETUP_WAIT_SECS" \
  || {
    echo "iPhone admin did not submit the macOS approval" >&2
    exit 1
  }
ios_admin_submitted_ms="$(
  ios_marker_value_from "$ios_admin_log" NVPN_RELEASE_JOIN_APPROVAL_SUBMITTED_MS
)"
[[ "$ios_admin_submitted_ms" =~ ^[0-9]+$ ]]
ios_admin_observed_submitted_ms="$(release_join_now_ms)"
wait_log_marker \
  "$desktop_ios_join_log" NVPN_RELEASE_JOIN_MANUAL_COMPLETE_MS \
  "$RELEASE_JOIN_DELIVERY_WAIT_SECS"
ios_admin_remote_completed_ms="$(release_join_now_ms)"
release_join_ios_finish_test \
  || {
    echo "iPhone admin did not retain the exact macOS joiner" >&2
    exit 1
  }
ios_admin_applied_ms="$(
  ios_marker_value_from "$ios_admin_log" NVPN_RELEASE_JOIN_ROSTER_APPLIED_MS
)"
[[ "$ios_admin_applied_ms" =~ ^[0-9]+$ ]]
ios_admin_remote_elapsed_ms=$((
  ios_admin_remote_completed_ms - ios_admin_observed_submitted_ms
))
ios_admin_phone_elapsed_ms=$((ios_admin_applied_ms - ios_admin_submitted_ms))
ios_admin_delivery_elapsed_ms="$ios_admin_remote_elapsed_ms"
((ios_admin_phone_elapsed_ms <= ios_admin_delivery_elapsed_ms)) \
  || ios_admin_delivery_elapsed_ms="$ios_admin_phone_elapsed_ms"
assert_delivery_duration \
  "$ios_admin_delivery_elapsed_ms" "iPhone-admin-to-macOS-manual"
ios_admin_relaunch_joiner="$(
  ios_marker_value_from \
    "$ios_admin_log" NVPN_RELEASE_JOIN_ADMIN_RELAUNCH_DURABLE
)"
[[ "$ios_admin_relaunch_joiner" == "$DESKTOP_IOS_JOINER_ID" ]] \
  || {
    echo "iPhone admin relaunch evidence did not name the exact macOS joiner" >&2
    exit 1
  }
IPHONE_ADMIN_DESKTOP_JOINER_RELAUNCH_DURABLE=1
finish_remote "$desktop_ios_join_log" \
  || {
    echo "macOS joiner did not receive the iPhone's signed roster" >&2
    exit 1
  }
remote verify "$RELEASE_JOIN_IOS_ADMIN_ID" \
  >"$RESULT_DIR/macos/desktop-ios-joiner-verify.log"
)
ios_admin_macos_status=$?
set -e
if ((ios_admin_macos_status != 0)); then
  echo "iPhone admin -> macOS joiner failed" >&2
else
  IPHONE_ADMIN_DESKTOP_JOINER_RELAUNCH_DURABLE=1
fi
finish_macos_mobile_direction iphone-admin-macos-joiner
release_join_launch_ios_release
release_join_assert_one_ios_process
fi

if ((macos_admin_android_status != 0 \
  || android_admin_macos_status != 0 \
  || macos_admin_ios_status != 0 \
  || ios_admin_macos_status != 0)); then
  echo "One or more macOS/mobile manual-join directions failed" >&2
  exit 1
fi

python3 - \
  "$RESULT_DIR/macos/summary.json" \
  "$RESULT_DIR/macos/delivery-times.tsv" \
  "$RESULT_DIR/macos/artifact.json" \
  "${NVPN_RELEASE_JOIN_IOS_RECEIPT:?exact retained iOS receipt is required}" \
  "$DESKTOP_ADMIN_IPHONE_JOINER_RELAUNCH_DURABLE" \
  "$IPHONE_ADMIN_DESKTOP_JOINER_RELAUNCH_DURABLE" \
  "$APP_GIT_SHA" \
  "$APP_GIT_TREE" \
  "$ANDROID_ARTIFACT_RECEIPT" \
  "$ANDROID_INSTALL_RECEIPT" \
  "$MACOS_MOBILE_DIRECTIONS" <<'PY'
import hashlib
import json
import pathlib
import sys

timings = {}
for line in pathlib.Path(sys.argv[2]).read_text(encoding="utf-8").splitlines():
    label, elapsed = line.split("\t")
    timings[label] = int(elapsed)
all_timings = {
    "macOS-admin-to-Android-manual",
    "Android-admin-to-macOS-manual",
    "macOS-admin-to-iPhone-manual",
    "iPhone-admin-to-macOS-manual",
}
pixel_timings = {
    "macOS-admin-to-Android-manual",
    "Android-admin-to-macOS-manual",
}
selected = sys.argv[11]
expected_timings = all_timings if selected == "all" else pixel_timings
if set(timings) != expected_timings or any(
    elapsed < 0 or elapsed > 15_000 for elapsed in timings.values()
):
    raise SystemExit("macOS/mobile join timing receipt is incomplete or slow")
artifact_path = pathlib.Path(sys.argv[3])
artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
component_proof = artifact.get("componentInputProof") or {}
ios_artifact_path = pathlib.Path(sys.argv[4])
ios_artifact = json.loads(ios_artifact_path.read_text(encoding="utf-8"))
(
    desktop_admin_iphone_joiner_relaunch,
    iphone_admin_desktop_joiner_relaunch,
    app_sha,
    app_tree,
    android_artifact_receipt_name,
    android_install_receipt_name,
) = sys.argv[5:11]
android_artifact_receipt = pathlib.Path(android_artifact_receipt_name)
android_install_receipt = pathlib.Path(android_install_receipt_name)
android_artifact = json.loads(
    android_artifact_receipt.read_text(encoding="utf-8")
)
android_install = json.loads(
    android_install_receipt.read_text(encoding="utf-8")
)
if selected == "all" and (
    desktop_admin_iphone_joiner_relaunch != "1"
    or iphone_admin_desktop_joiner_relaunch != "1"
):
    raise SystemExit("macOS/iPhone directional relaunch evidence is incomplete")
if (
    artifact.get("receiptSchema") != 1
    or component_proof.get("candidate_app_git_sha") != app_sha
    or component_proof.get("candidate_app_git_tree") != app_tree
    or not artifact.get("appGitSha")
    or not artifact.get("appGitTree")
    or artifact.get("companySigningVerified") is not True
    or not artifact.get("appExecutableSha256")
):
    raise SystemExit("macOS join artifact receipt is not exact")
ios_identity_keys = (
    "appGitSha",
    "appGitTree",
    "fipsGitSha",
    "fipsGitTree",
    "appBundleTreeSha256",
    "appCodeDirectoryHash",
    "packetTunnelCodeDirectoryHash",
    "appExecutableSha256",
    "packetTunnelExecutableSha256",
    "signerCertificateSha256",
    "installedBundleIdentifier",
)
if (
    ios_artifact.get("receiptSchema") != 2
    or ios_artifact.get("artifactType")
    != "iOS Ad Hoc Release join-test variant"
    or ios_artifact.get("companySigningVerified") is not True
    or any(not ios_artifact.get(key) for key in ios_identity_keys)
):
    raise SystemExit("iPhone join artifact receipt is not exact")
android_identity_keys = (
    "appGitSha",
    "appGitTree",
    "fipsGitSha",
    "fipsGitTree",
    "apkSha256",
    "installedApkSha256",
    "package",
    "signerCertificateSha256",
)
if (
    android_artifact.get("receiptSchema") != 2
    or android_artifact.get("artifactType") != "Android Release APK"
    or any(not android_artifact.get(key) for key in android_identity_keys)
    or any(
        android_install.get(key) != android_artifact.get(key)
        for key in android_identity_keys
    )
):
    raise SystemExit("Android join artifact/install receipt pair is not exact")
with open(sys.argv[1], "w", encoding="utf-8") as handle:
    json.dump(
        {
            "schema": 1,
            "platform": "macos",
            "artifact": {
                "type": "signed macOS Release app",
                "appGitSha": artifact["appGitSha"],
                "appGitTree": artifact["appGitTree"],
                "harnessGitSha": app_sha,
                "harnessGitTree": app_tree,
                "artifactReceiptSha256": hashlib.sha256(
                    artifact_path.read_bytes()
                ).hexdigest(),
                "appExecutableSha256": artifact["appExecutableSha256"],
                "android": {
                    "artifactReceiptSha256": hashlib.sha256(
                        android_artifact_receipt.read_bytes()
                    ).hexdigest(),
                    "artifactReceiptSize": android_artifact_receipt.stat().st_size,
                    "installReceiptSha256": hashlib.sha256(
                        android_install_receipt.read_bytes()
                    ).hexdigest(),
                    "installReceiptSize": android_install_receipt.stat().st_size,
                    **{
                        key: android_artifact[key]
                        for key in android_identity_keys
                    },
                },
                "ios": {
                    "artifactReceiptSha256": hashlib.sha256(
                        ios_artifact_path.read_bytes()
                    ).hexdigest(),
                    **{
                        key: ios_artifact[key]
                        for key in ios_identity_keys
                    },
                },
            },
            "builtOnHost": True,
            "builtOnTestVm": False,
            "remoteImportVerified": True,
            "publicUiOnly": True,
            "appLaunchArgumentsOrEnvironment": False,
            "privateAppStateRead": False,
            "privateStateRead": False,
            "fixtureInvoked": False,
            "acceptedSelectorSemantics": "participant-state-not-pending",
            "selectedDirections": selected,
            "desktopAdminAndroidJoiner": True,
            "androidAdminDesktopJoiner": True,
            "desktopAdminIphoneJoiner": selected == "all",
            "iphoneAdminDesktopJoiner": selected == "all",
            "exactRosterOnBothSides": True,
            "acceptedRosterRetainedAcrossRelaunch": True,
            "desktopRelaunchDurability": True,
            "pixelRelaunchDurability": True,
            "desktopAdminIphoneJoinerRelaunchDurable":
                selected == "all" and desktop_admin_iphone_joiner_relaunch == "1",
            "iphoneAdminDesktopJoinerRelaunchDurable":
                selected == "all" and iphone_admin_desktop_joiner_relaunch == "1",
            "deliveryDeadlineMilliseconds": 15_000,
            "deliveryMilliseconds": timings,
        },
        handle,
        indent=2,
        sort_keys=True,
    )
    handle.write("\n")
PY

echo "SIGNED_RELEASE_PUBLIC_UI_DESKTOP_MOBILE_JOIN_E2E_OK"
