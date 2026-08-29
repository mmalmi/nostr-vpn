#!/usr/bin/env bash
# macOS VM half of the Release desktop <-> mobile manual-join gate.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP_ROOT="${NVPN_APP_REPO_PATH:-$ROOT}"
EXTERNAL_HARNESS_DIGEST="${NVPN_EXTERNAL_HARNESS_DIGEST:-}"
REMOTE_HARNESS_FILES=(
  scripts/lib-macos-release-app-ownership.sh
  scripts/macos-release-mobile-join-remote.sh
  scripts/macos_release_join_artifact.py
  scripts/mobile_release_artifact_receipt.py
)
ACTUAL_HARNESS_DIGEST="$(
  for file in "${REMOTE_HARNESS_FILES[@]}"; do
    printf '%s\t%s\n' \
      "$file" "$(shasum -a 256 "$ROOT/$file" | awk '{print $1}')"
  done | shasum -a 256 | awk '{print $1}'
)"
[[ "$EXTERNAL_HARNESS_DIGEST" =~ ^[0-9a-f]{64}$ \
  && "$(basename "$ROOT")" == "$EXTERNAL_HARNESS_DIGEST" \
  && "$ACTUAL_HARNESS_DIGEST" == "$EXTERNAL_HARNESS_DIGEST" ]] || {
  echo "macOS Release join external harness identity is invalid" >&2
  exit 2
}
# shellcheck disable=SC1091
source "$ROOT/scripts/lib-macos-release-app-ownership.sh"
ARTIFACT_DIR="${NVPN_MACOS_RELEASE_JOIN_ARTIFACT_DIR:-$ROOT/artifacts/macos-release-mobile-join}"
PACKAGE="$ARTIFACT_DIR/imported"
APP_PATH="$PACKAGE/Nostr VPN.app"
APP_EXE="$APP_PATH/Contents/MacOS/Nostr VPN"
CLI="$APP_PATH/Contents/Resources/nvpn"
MANUAL_JOIN_FIXTURE="$PACKAGE/fixtures/desktop_manual_join_e2e_fixture"
MANUAL_JOIN_DRIVER="$PACKAGE/drivers/desktop-manual-join-ax"
SERVICE_TOGGLE_DRIVER="$PACKAGE/drivers/macos-service-toggle-ax"
COMPONENT_PROOF="$PACKAGE/component-proof.json"
FIPS_PATH="${NVPN_FIPS_REPO_PATH:-$ROOT/../fips}"
ARCHIVE="$ARTIFACT_DIR/macos-release-gate.zip"
RECEIPT="$ARTIFACT_DIR/artifact.json"
EXPECTED_APP="${NVPN_EXPECTED_APP_GIT_SHA:-}"
EXPECTED_APP_TREE="${NVPN_EXPECTED_APP_GIT_TREE:-}"
EXPECTED_HARNESS="${NVPN_EXPECTED_HARNESS_GIT_SHA:-}"
EXPECTED_HARNESS_TREE="${NVPN_EXPECTED_HARNESS_GIT_TREE:-}"
EXPECTED_FIPS="${NVPN_EXPECTED_FIPS_GIT_SHA:-}"
EXPECTED_FIPS_TREE="${NVPN_EXPECTED_FIPS_GIT_TREE:-}"
EXPECTED_FIPS_VERSION="${NVPN_EXPECTED_FIPS_VERSION:-}"
EXPECTED_SIGNING_IDENTITY="${NVPN_EXPECTED_MACOS_SIGNING_IDENTITY_SHA1:-}"
EXPECTED_SIGNING_TEAM="${NVPN_EXPECTED_MACOS_SIGNING_TEAM_ID:-}"
EXPECTED_SIGNER_CERT_SHA256="${NVPN_EXPECTED_MACOS_SIGNER_CERT_SHA256:-}"
APP_LOG="$ARTIFACT_DIR/app.log"
APP_PID=""
MACOS_RELEASE_APP_STATE_DIR="$ARTIFACT_DIR/app-ownership"
MACOS_RELEASE_APP_INSTALLED_EXE="/Applications/Nostr VPN.app/Contents/MacOS/Nostr VPN"
MACOS_RELEASE_APP_GATE_EXE="$APP_EXE"
MACOS_RELEASE_APP_PROCESS_NAME="Nostr VPN"
OWNED_PID_FILE="$MACOS_RELEASE_APP_STATE_DIR/imported.pid"
CONFIG_DIR="$HOME/Library/Application Support/nvpn"
PROFILE_STATE_DIR="${NVPN_MACOS_RELEASE_JOIN_PROFILE_STATE_DIR:-$HOME/Library/Caches/nvpn-release-mobile-join-profile}"
CONFIG_BACKUP="$PROFILE_STATE_DIR/prior"
# Short and stable for macOS sockaddr_un and interrupted-run cleanup.
TEST_CONFIG_DIR="/tmp/nvpn-rj-$UID"
CONFIG="$TEST_CONFIG_DIR/config.toml"
DAEMON_LOG="$TEST_CONFIG_DIR/daemon.log"
TEST_PROFILE_MARKER="$PROFILE_STATE_DIR/state"
TEST_SERVICE_OWNED="$PROFILE_STATE_DIR/service-owned"
IMPORT_VERIFIED="$ARTIFACT_DIR/import-verified"

mkdir -p "$ARTIFACT_DIR"

stop_app() {
  if [[ -n "$APP_PID" ]]; then
    if kill -0 "$APP_PID" >/dev/null 2>&1; then
      macos_release_app_stop_pid "$APP_PID" "$APP_EXE"
    fi
    rm -f "$OWNED_PID_FILE"
  fi
  APP_PID=""
}
trap stop_app EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

load_app() {
  [[ -x "$APP_EXE" && -x "$CLI" ]] || {
    echo "Signed macOS Release app is missing: $APP_PATH" >&2
    return 1
  }
  codesign --verify --deep --strict "$APP_PATH"
}

assert_service_ready() {
  local expected_hash service_json runtime_json
  expected_hash="$(shasum -a 256 "$CLI" | awk '{ print $1 }')"
  local deadline=$((SECONDS + 15))
  while ((SECONDS < deadline)); do
    service_json="$(
      "$CLI" service status --json --skip-binary-version \
        --config "$CONFIG" 2>/dev/null || true
    )"
    if python3 -c '
import hashlib,json,pathlib,sys
v=json.loads(sys.argv[1]); p=pathlib.Path(v["binary_path"])
assert v.get("installed") is True and v.get("loaded") is True
assert v.get("running") is True and int(v.get("pid", 0)) > 1
assert hashlib.sha256(p.read_bytes()).hexdigest() == sys.argv[2]
' "$service_json" "$expected_hash" 2>/dev/null
    then
      runtime_json="$(
        "$CLI" status --json --discover-secs 0 --config "$CONFIG" \
          2>/dev/null || true
      )"
      if python3 -c '
import json,sys
assert json.loads(sys.argv[1]).get("daemon", {}).get("running") is True
' "$runtime_json" 2>/dev/null
      then
        echo "NVPN_RELEASE_JOIN_MARKER NVPN_MACOS_RELEASE_SERVICE_READY=1"
        return 0
      fi
    fi
    sleep 0.2
  done
  echo "macOS Release join shipped service did not become ready" >&2
  "$CLI" service status --json --config "$CONFIG" >&2 || true
  tail -n 120 "$DAEMON_LOG" >&2 2>/dev/null || true
  return 1
}

assert_join_listener_ready() {
  assert_service_ready >/dev/null
  local runtime_json deadline=$((SECONDS + 15))
  while ((SECONDS < deadline)); do
    runtime_json="$(
      "$CLI" status --json --include-join-request --discover-secs 0 \
        --config "$CONFIG" \
        2>/dev/null || true
    )"
    if python3 -c '
import json,sys
v=json.loads(sys.argv[1]); d=v.get("daemon", {}); s=d.get("state") or {}
listener_ready = (
    int(v.get("expected_peer_count", -1)) == 0
    and s.get("vpn_enabled") is True
    and s.get("vpn_active") is False
    and s.get("vpn_status") == "Waiting for participants"
    and bool(v.get("network_id"))
)
assert d.get("running") is True and listener_ready
' "$runtime_json" 2>/dev/null
    then
      echo "NVPN_RELEASE_JOIN_MARKER NVPN_MACOS_RELEASE_JOIN_LISTENER_READY=1"
      return 0
    fi
    sleep 0.2
  done
  echo "macOS Release join listener did not become ready" >&2
  printf '%s\n' "$runtime_json" >&2
  tail -n 120 "$DAEMON_LOG" >&2 2>/dev/null || true
  return 1
}

swap_test_profile() {
  [[ ! -e "$TEST_PROFILE_MARKER" && ! -e "$CONFIG_BACKUP" \
    && ! -e "$TEST_CONFIG_DIR" ]] || {
    echo "stale macOS Release join profile transaction exists" >&2
    return 1
  }
  mkdir -p "$(dirname "$CONFIG_DIR")" "$PROFILE_STATE_DIR"
  chmod 700 "$PROFILE_STATE_DIR"
  if [[ -e "$CONFIG_DIR" ]]; then
    [[ -d "$CONFIG_DIR" && ! -L "$CONFIG_DIR" ]] || {
      echo "refusing non-directory macOS profile state: $CONFIG_DIR" >&2
      return 1
    }
    mv "$CONFIG_DIR" "$CONFIG_BACKUP"
    printf 'prior\n' >"$TEST_PROFILE_MARKER"
  else
    printf 'absent\n' >"$TEST_PROFILE_MARKER"
  fi
  mkdir -m 700 "$TEST_CONFIG_DIR"
  ln -s "$TEST_CONFIG_DIR" "$CONFIG_DIR"
}

restore_config_dir() {
  [[ -f "$TEST_PROFILE_MARKER" ]] || return 0
  local prior
  prior="$(<"$TEST_PROFILE_MARKER")"
  [[ -L "$CONFIG_DIR" \
    && "$(readlink "$CONFIG_DIR")" == "$TEST_CONFIG_DIR" ]] || return 1
  rm "$CONFIG_DIR"
  case "$prior" in
    prior) mv "$CONFIG_BACKUP" "$CONFIG_DIR" ;;
    absent) [[ ! -e "$CONFIG_BACKUP" ]] ;;
    *) return 1 ;;
  esac
  rm -f "$TEST_PROFILE_MARKER"
  if ! rm -rf "$TEST_CONFIG_DIR"; then
    local quarantine="${TEST_CONFIG_DIR}.quarantine.$(date -u +%Y%m%dT%H%M%SZ).$$"
    if mv "$TEST_CONFIG_DIR" "$quarantine"; then
      echo "quarantined privileged macOS Release join test profile: $quarantine" >&2
    else
      echo "could not quarantine privileged macOS Release join test profile" >&2
      return 1
    fi
  fi
  rmdir "$PROFILE_STATE_DIR" 2>/dev/null || true
}

restore_test_profile() {
  [[ -e "$TEST_PROFILE_MARKER" || -e "$TEST_SERVICE_OWNED" ]] || return 0
  stop_app
  if [[ -e "$TEST_SERVICE_OWNED" ]]; then
    local service_pid deadline
    service_pid="$(
      "$CLI" service status --json --skip-binary-version --config "$CONFIG" \
        2>/dev/null || true
    )"
    service_pid="$(python3 -c '
import json,sys
value=json.loads(sys.argv[1]).get("pid")
print(value if isinstance(value, int) and value > 1 else "")
' "$service_pid" 2>/dev/null || true)"
    sudo -n "$CLI" service uninstall --config "$CONFIG" >/dev/null
    deadline=$((SECONDS + 15))
    while [[ -n "$service_pid" ]] \
      && ps -p "$service_pid" -o pid= >/dev/null 2>&1 \
      && ((SECONDS < deadline))
    do
      sleep 0.2
    done
    if [[ -n "$service_pid" ]] \
      && ps -p "$service_pid" -o pid= >/dev/null 2>&1
    then
      echo "macOS Release join service did not fully stop during cleanup" >&2
      return 1
    fi
    rm -f "$TEST_SERVICE_OWNED"
  fi
  restore_config_dir
}

service_preflight() {
  [[ -f "$IMPORT_VERIFIED" && -x "$CLI" ]] || {
    echo "macOS Release join import was not verified" >&2
    return 1
  }
  macos_release_app_acquire
  local status
  status="$(
    "$CLI" service status --json --skip-binary-version --config "$CONFIG" \
      2>/dev/null || true
  )"
  python3 -c '
import json,sys
v=json.loads(sys.argv[1]); assert not v.get("installed") and not v.get("running")
' "$status" 2>/dev/null || { echo "macOS Release join requires an empty service slot" >&2; return 1; }
  swap_test_profile
  "$CLI" init --config "$CONFIG" --force >/dev/null
  : >"$TEST_SERVICE_OWNED"
  if ! sudo -n "$CLI" service install --force --config "$CONFIG" >/dev/null; then
    restore_test_profile
    return 1
  fi
  assert_service_ready
}

daemon_log_offset() {
  [[ -f "$DAEMON_LOG" ]] && stat -f %z "$DAEMON_LOG" || printf '0\n'
}

require_delivery_log() {
  local recipient_hex offset="$2" expected delta deadline=$((SECONDS + 3))
  recipient_hex="$("$MANUAL_JOIN_FIXTURE" normalize-npub "$1")"
  [[ "$recipient_hex" =~ ^[0-9a-f]{64}$ && "$offset" =~ ^[0-9]+$ ]] || return 2
  expected="delivered and applied one signed join roster over FIPS-TCP to $recipient_hex"
  delta="$ARTIFACT_DIR/delivery-daemon-delta.log"
  while ((SECONDS < deadline)); do
    tail -c "+$((offset + 1))" "$DAEMON_LOG" >"$delta" 2>/dev/null || true
    if grep -Fxq "$expected" "$delta"; then
      cat "$delta" >&2
      printf '%s\n' "$expected"
      return 0
    fi
    sleep 0.1
  done
  cat "$delta" >&2 2>/dev/null || true
  echo "macOS daemon did not confirm recipient-specific durable delivery" >&2
  return 1
}

verify_import() {
  [[ -s "$ARCHIVE" && -s "$RECEIPT" && -d "$PACKAGE" ]] || {
    echo "Host-built macOS Release gate package is incomplete" >&2
    return 1
  }
  python3 "$ROOT/scripts/macos_release_join_artifact.py" validate \
    --receipt "$RECEIPT" \
    --package "$PACKAGE" \
    --app "$APP_PATH" \
    --archive "$ARCHIVE" \
    --manual-join-fixture "$MANUAL_JOIN_FIXTURE" \
    --manual-join-driver "$MANUAL_JOIN_DRIVER" \
    --service-toggle-driver "$SERVICE_TOGGLE_DRIVER" \
    --component-proof "$COMPONENT_PROOF" \
    --app-root "$APP_ROOT" \
    --fips-root "$FIPS_PATH" \
    --expected-app-head "$EXPECTED_APP" \
    --expected-app-tree "$EXPECTED_APP_TREE" \
    --expected-harness-head "$EXPECTED_HARNESS" \
    --expected-harness-tree "$EXPECTED_HARNESS_TREE" \
    --expected-fips-head "$EXPECTED_FIPS" \
    --expected-fips-tree "$EXPECTED_FIPS_TREE" \
    --expected-fips-version "$EXPECTED_FIPS_VERSION" \
    --expected-team "$EXPECTED_SIGNING_TEAM" \
    --expected-identity-sha1 "$EXPECTED_SIGNING_IDENTITY" \
    --expected-signer-sha256 "$EXPECTED_SIGNER_CERT_SHA256" \
    --verification-output "$ARTIFACT_DIR/verification.json"
  load_app
}

launch_app() {
  [[ -f "$IMPORT_VERIFIED" ]] || {
    echo "macOS Release join import was not verified" >&2
    return 1
  }
  macos_release_app_acquire
  [[ ! -f "$OWNED_PID_FILE" ]] || {
    echo "a previous imported app launch is still owned" >&2
    return 1
  }
  (
    exec /usr/bin/env -i \
      HOME="$HOME" \
      USER="${USER:-dev}" \
      LOGNAME="${LOGNAME:-${USER:-dev}}" \
      PATH=/usr/bin:/bin:/usr/sbin:/sbin \
      TMPDIR="${TMPDIR:-/tmp}" \
      LANG="${LANG:-en_US.UTF-8}" \
      NVPN_APP_DATA_DIR="$TEST_CONFIG_DIR" \
      "$APP_EXE"
  ) >>"$APP_LOG" 2>&1 &
  APP_PID=$!
  printf '%s\n' "$APP_PID" >"$OWNED_PID_FILE.tmp"
  mv "$OWNED_PID_FILE.tmp" "$OWNED_PID_FILE"
  local deadline=$((SECONDS + 10))
  while ((SECONDS < deadline)); do
    kill -0 "$APP_PID" >/dev/null 2>&1 && return 0
    sleep 0.1
  done
  return 1
}

run_driver() {
  local phase="$1" value1="$2" value2="$3"
  launch_app
  "$MANUAL_JOIN_DRIVER" \
    "$APP_PID" "$phase" "$value1" "$value2" "Nostr VPN"
  stop_app
}

run_manual_join_driver() {
  run_driver release-manual-join "$1" "$2"
}

run_driver_hold() {
  local phase="$1" value1="$2" value2="$3"
  launch_app
  "$MANUAL_JOIN_DRIVER" \
    "$APP_PID" "$phase" "$value1" "$value2" "Nostr VPN"
  echo "NVPN_RELEASE_JOIN_MARKER NVPN_MACOS_RELEASE_APP_HOLDING=1"
  sleep "${NVPN_MACOS_RELEASE_JOIN_HOLD_SECS:-20}"
  stop_app
}

stage() {
  stop_app
  restore_test_profile
  macos_release_app_restore
  rm -rf "$ARTIFACT_DIR"
  mkdir -p "$ARTIFACT_DIR"
}

prepare() {
  local import_dir="$ARTIFACT_DIR/import"
  [[ -s "$ARCHIVE" && -s "$RECEIPT" ]] || {
    echo "Host-built macOS Release app archive or receipt is missing" >&2
    return 1
  }
  rm -rf "$import_dir" "$PACKAGE"
  mkdir -p "$import_dir"
  ditto -x -k "$ARCHIVE" "$import_dir"
  [[ -d "$import_dir/package/Nostr VPN.app" \
    && -s "$import_dir/package/component-proof.json" \
    && -x "$import_dir/package/fixtures/desktop_manual_join_e2e_fixture" \
    && -x "$import_dir/package/drivers/desktop-manual-join-ax" \
    && -x "$import_dir/package/drivers/macos-service-toggle-ax" \
    && "$(find "$import_dir" -mindepth 1 -maxdepth 1 | wc -l | tr -d ' ')" == 1 ]] || {
    echo "Imported macOS Release archive has an unexpected root layout" >&2
    return 1
  }
  mv "$import_dir/package" "$PACKAGE"
  rmdir "$import_dir"
  verify_import
  : >"$IMPORT_VERIFIED"
  echo "NVPN_RELEASE_JOIN_MARKER NVPN_MACOS_RELEASE_ARTIFACT_READY=1"
}

case "${1:-}" in
  stage)
    stage
    ;;
  prepare)
    prepare
    ;;
  verify-import)
    verify_import
    : >"$IMPORT_VERIFIED"
    echo "NVPN_RELEASE_JOIN_MARKER NVPN_MACOS_RELEASE_ARTIFACT_VERIFIED=1"
    ;;
  create-admin)
    [[ $# == 2 ]] || { echo "usage: $0 create-admin <network-name>" >&2; exit 2; }
    run_driver release-create-admin "$2" _
    assert_join_listener_ready
    ;;
  joiner-id)
    [[ $# == 1 ]] || { echo "usage: $0 joiner-id" >&2; exit 2; }
    run_driver release-joiner-id _ _
    ;;
  manual-join)
    [[ $# == 3 ]] || { echo "usage: $0 manual-join <admin-npub> <network-id>" >&2; exit 2; }
    run_manual_join_driver "$2" "$3"
    ;;
  admin-add)
    [[ $# == 3 ]] || { echo "usage: $0 admin-add <joiner-npub> <alias>" >&2; exit 2; }
    run_driver_hold release-admin-add "$2" "$3"
    ;;
  verify)
    [[ $# == 2 ]] || { echo "usage: $0 verify <participant-npub>" >&2; exit 2; }
    run_driver release-verify "$2" _
    ;;
  service-preflight)
    [[ $# == 1 ]] || { echo "usage: $0 service-preflight" >&2; exit 2; }
    service_preflight
    ;;
  daemon-log-offset)
    [[ $# == 1 ]] || { echo "usage: $0 daemon-log-offset" >&2; exit 2; }
    daemon_log_offset
    ;;
  require-delivery-log)
    [[ $# == 3 ]] || { echo "usage: $0 require-delivery-log <recipient-npub> <offset>" >&2; exit 2; }
    require_delivery_log "$2" "$3"
    ;;
  cleanup)
    restore_test_profile
    macos_release_app_restore
    rm -rf "$ROOT"
    ;;
  reset-profile)
    restore_test_profile
    macos_release_app_restore
    ;;
  *)
    echo "usage: $0 <stage|prepare|verify-import|service-preflight|daemon-log-offset|require-delivery-log|create-admin|joiner-id|manual-join|admin-add|verify|reset-profile|cleanup>" >&2
    exit 2
    ;;
esac
