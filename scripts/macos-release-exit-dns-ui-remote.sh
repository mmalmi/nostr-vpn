#!/usr/bin/env bash
# macOS VM half of the exact imported Release Exit DNS public-UI gate.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "$ROOT/scripts/lib-macos-owned-test-app.sh"
IMPORT_DIR="${NVPN_MACOS_RELEASE_JOIN_ARTIFACT_DIR:-$ROOT/artifacts/macos-release-mobile-join}"
PACKAGE="$IMPORT_DIR/imported"
APP_PATH="$PACKAGE/Nostr VPN.app"
APP_EXE="$APP_PATH/Contents/MacOS/Nostr VPN"
APP_RECEIPT="$IMPORT_DIR/artifact.json"
IMPORT_VERIFICATION="$IMPORT_DIR/verification.json"
ARTIFACT_DIR="${NVPN_MACOS_EXIT_DNS_UI_ARTIFACT_DIR:-$ROOT/artifacts/macos-exit-dns-ui}"
DRIVER="$ARTIFACT_DIR/support/macos-exit-dns-ax"
DRIVER_RECEIPT="$ARTIFACT_DIR/driver-receipt.json"
DRIVER_VERIFICATION="$ARTIFACT_DIR/driver-verification.json"
OBSERVATIONS="$ARTIFACT_DIR/observations"
RESULTS="$ARTIFACT_DIR/results"
RESTORATION="$ARTIFACT_DIR/restoration.json"
FIPS_PATH="${NVPN_FIPS_REPO_PATH:-$ROOT/../fips}"
EXPECTED_APP="${NVPN_EXPECTED_APP_GIT_SHA:-}"
EXPECTED_APP_TREE="${NVPN_EXPECTED_APP_GIT_TREE:-}"
EXPECTED_FIPS="${NVPN_EXPECTED_FIPS_GIT_SHA:-}"
EXPECTED_FIPS_TREE="${NVPN_EXPECTED_FIPS_GIT_TREE:-}"
EXPECTED_FIPS_VERSION="${NVPN_EXPECTED_FIPS_VERSION:-}"
EXPECTED_IDENTITY="${NVPN_EXPECTED_MACOS_SIGNING_IDENTITY_SHA1:-}"
EXPECTED_TEAM="${NVPN_EXPECTED_MACOS_SIGNING_TEAM_ID:-}"
EXPECTED_SIGNER="${NVPN_EXPECTED_MACOS_SIGNER_CERT_SHA256:-}"
EXPECTED_IMPORT_VERIFICATION_SHA256="${NVPN_EXPECTED_MACOS_IMPORT_VERIFICATION_SHA256:-}"
CANONICAL_DATA="$HOME/Library/Application Support/nvpn"
BACKUP_ROOT="/tmp/nvpn-macos-exit-dns-profile-backup"
INSTALLED_APP_PATH="/Applications/Nostr VPN.app"
INSTALLED_APP="/Applications/Nostr VPN.app/Contents/MacOS/Nostr VPN"
APP_PID=""

macos_open() {
  /usr/bin/env -i \
    HOME="$HOME" \
    USER="${USER:-dev}" \
    LOGNAME="${LOGNAME:-${USER:-dev}}" \
    PATH=/usr/bin:/bin:/usr/sbin:/sbin \
    TMPDIR="${TMPDIR:-/tmp}" \
    LANG="${LANG:-en_US.UTF-8}" \
    /usr/bin/open "$@"
}

stop_gate_app() {
  macos_stop_exact_test_app "$APP_EXE"
  APP_PID=""
}

stop_all_apps() {
  stop_gate_app
  macos_stop_exact_test_app "$INSTALLED_APP"
}

installed_app_running() {
  [[ -n "$(macos_exact_executable_pids "$INSTALLED_APP")" ]]
}

restore_profile() {
  [[ -d "$BACKUP_ROOT" ]] || {
    stop_gate_app
    return 0
  }
  stop_all_apps || true
  if [[ -d "$BACKUP_ROOT/profile" ]]; then
    [[ "$CANONICAL_DATA" == "$HOME/Library/Application Support/nvpn" ]]
    [[ ! -L "$CANONICAL_DATA" ]]
    rm -rf "$CANONICAL_DATA"
    mkdir -p "$(dirname "$CANONICAL_DATA")"
    mv "$BACKUP_ROOT/profile" "$CANONICAL_DATA"
  elif [[ -f "$BACKUP_ROOT/original-absent" ]]; then
    [[ "$CANONICAL_DATA" == "$HOME/Library/Application Support/nvpn" ]]
    [[ ! -L "$CANONICAL_DATA" ]]
    rm -rf "$CANONICAL_DATA"
  fi
  local relaunched=false
  if [[ -f "$BACKUP_ROOT/installed-was-running" && -x "$INSTALLED_APP" ]]; then
    macos_open -n -F -j "$INSTALLED_APP_PATH" --args --hidden
    local deadline=$((SECONDS + 5))
    while ((SECONDS < deadline)); do
      if installed_app_running; then
        relaunched=true
        break
      fi
      sleep 0.1
    done
  fi
  if [[ -d "$BACKUP_ROOT" ]]; then
    local was_running=false
    [[ -f "$BACKUP_ROOT/installed-was-running" ]] && was_running=true
    python3 - "$RESTORATION" "$was_running" "$relaunched" <<'PY'
import json
import pathlib
import sys

output, was_running, relaunched = sys.argv[1:]
value = {
    "receiptSchema": 1,
    "canonicalProfileRestored": True,
    "preexistingAppStateRestored": True,
    "gateAppProcessesStopped": True,
    "preexistingInstalledAppWasRunning": was_running == "true",
    "preexistingInstalledAppRelaunched": relaunched == "true",
}
if value["preexistingInstalledAppWasRunning"] != value[
    "preexistingInstalledAppRelaunched"
]:
    raise SystemExit("installed app running state was not restored")
pathlib.Path(output).write_text(
    json.dumps(value, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
PY
    rm -rf "$BACKUP_ROOT"
  fi
}

cleanup() {
  restore_profile
}

launch_app() {
  stop_all_apps
  [[ -x "$APP_EXE" ]] || {
    echo "exact imported macOS Release executable is missing" >&2
    return 1
  }
  codesign --verify --deep --strict "$APP_PATH"
  macos_open -n -F \
    --stdout "$ARTIFACT_DIR/app.log" \
    --stderr "$ARTIFACT_DIR/app.log" \
    "$APP_PATH"
  local deadline=$((SECONDS + 20))
  while ((SECONDS < deadline)); do
    APP_PID="$(macos_exact_executable_pids "$APP_EXE" | tail -n 1)"
    if [[ -n "$APP_PID" ]] && kill -0 "$APP_PID" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.1
  done
  echo "exact imported macOS Release app did not launch through LaunchServices" >&2
  return 1
}

verify_artifacts() {
  [[ "$EXPECTED_IMPORT_VERIFICATION_SHA256" =~ ^[0-9a-f]{64}$ ]] || {
    echo "exact external import-verification digest is required" >&2
    return 1
  }
  [[ "$(shasum -a 256 "$IMPORT_VERIFICATION" | awk '{ print $1 }')" \
    == "$EXPECTED_IMPORT_VERIFICATION_SHA256" ]] || {
    echo "import-verification receipt differs from the controller evidence" >&2
    return 1
  }
  python3 "$ROOT/scripts/macos_exit_dns_ui_receipt.py" validate-driver \
    --receipt "$DRIVER_RECEIPT" \
    --verification-output "$DRIVER_VERIFICATION" \
    --driver "$DRIVER" \
    --driver-source "$ROOT/scripts/macos-exit-dns-ax.swift" \
    --app "$APP_PATH" \
    --app-receipt "$APP_RECEIPT" \
    --app-root "$ROOT" \
    --expected-app-head "$EXPECTED_APP" \
    --expected-app-tree "$EXPECTED_APP_TREE" \
    --expected-team "$EXPECTED_TEAM" \
    --expected-identity-sha1 "$EXPECTED_IDENTITY" \
    --expected-signer-sha256 "$EXPECTED_SIGNER"
  "$DRIVER" --check-accessibility
}

prepare_profile() {
  [[ ! -e "$BACKUP_ROOT" ]] || {
    echo "stale macOS Exit DNS profile backup exists" >&2
    return 1
  }
  [[ "$CANONICAL_DATA" == "$HOME/Library/Application Support/nvpn" ]]
  [[ ! -L "$CANONICAL_DATA" ]] || {
    echo "refusing symlinked canonical macOS app profile" >&2
    return 1
  }
  mkdir -p "$BACKUP_ROOT"
  installed_app_running && touch "$BACKUP_ROOT/installed-was-running"
  stop_all_apps
  if [[ -d "$CANONICAL_DATA" ]]; then
    mv "$CANONICAL_DATA" "$BACKUP_ROOT/profile"
  elif [[ -e "$CANONICAL_DATA" ]]; then
    echo "canonical macOS app profile is not a directory" >&2
    return 1
  else
    touch "$BACKUP_ROOT/original-absent"
  fi
}

run_case() {
  local case="$1"
  local apply="$OBSERVATIONS/$case-apply.json"
  local readback="$OBSERVATIONS/$case-readback.json"
  launch_app
  "$DRIVER" "$APP_PID" apply "$case" "$apply" "Nostr VPN"
  stop_gate_app
  launch_app
  "$DRIVER" "$APP_PID" readback "$case" "$readback" "Nostr VPN"
  stop_gate_app
  python3 "$ROOT/scripts/macos_exit_dns_ui_receipt.py" create-case \
    --case "$case" \
    --apply-observation "$apply" \
    --readback-observation "$readback" \
    --app-receipt "$APP_RECEIPT" \
    --driver-receipt "$DRIVER_RECEIPT" \
    --import-verification "$IMPORT_VERIFICATION" \
    --driver-verification "$DRIVER_VERIFICATION" \
    --output "$RESULTS/$case.json"
}

run_seller_case() {
  local apply="$OBSERVATIONS/paid-exit-seller-apply.json"
  local readback="$OBSERVATIONS/paid-exit-seller-readback.json"
  launch_app
  "$DRIVER" "$APP_PID" apply paid-exit-seller "$apply" "Nostr VPN"
  stop_gate_app
  launch_app
  "$DRIVER" "$APP_PID" readback paid-exit-seller "$readback" "Nostr VPN"
  stop_gate_app
  python3 "$ROOT/scripts/macos_exit_dns_ui_receipt.py" create-seller \
    --apply-observation "$apply" \
    --readback-observation "$readback" \
    --app-receipt "$APP_RECEIPT" \
    --driver-receipt "$DRIVER_RECEIPT" \
    --import-verification "$IMPORT_VERIFICATION" \
    --driver-verification "$DRIVER_VERIFICATION" \
    --output "$RESULTS/paid-exit-seller.json"
}

run_gate() {
  verify_artifacts
  rm -rf "$OBSERVATIONS" "$RESULTS"
  rm -f "$RESTORATION" "$ARTIFACT_DIR/app.log"
  mkdir -p "$OBSERVATIONS" "$RESULTS"
  trap cleanup EXIT
  prepare_profile
  local case
  for case in automatic cloudflare quad9 custom through-exit; do
    run_case "$case"
  done
  run_seller_case
  restore_profile
  trap - EXIT
  [[ -s "$RESTORATION" ]]
  echo "MACOS_RELEASE_EXIT_DNS_UI_E2E_OK"
}

stage() {
  [[ ! -e "$BACKUP_ROOT" ]] || {
    echo "stale macOS Exit DNS profile backup exists; run cleanup first" >&2
    return 1
  }
  rm -rf "$ARTIFACT_DIR"
  mkdir -p "$ARTIFACT_DIR/support"
}

case "${1:-}" in
  stage)
    stage
    ;;
  run)
    run_gate
    ;;
  cleanup)
    cleanup
    ;;
  *)
    echo "usage: $0 <stage|run|cleanup>" >&2
    exit 2
    ;;
esac
