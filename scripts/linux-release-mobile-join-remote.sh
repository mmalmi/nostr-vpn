#!/usr/bin/env bash
# Execute one public-GTK desktop/mobile join action on the Ubuntu VM.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODE="${1:-}"
ARTIFACT_ROOT="${2:-}"
APP="${3:-}"
CLI="${4:-}"
RECEIPT="${5:-}"
PACKAGE_RECEIPT="${6:-}"
shift $(( $# >= 6 ? 6 : $# ))

usage() {
  echo "usage: $0 <Reset|Bootstrap|InstallService|CreateAdmin|AdminAdd|ManualJoin|Verify|ReadMarker|ReadReceipt|ReadDaemonLog|Stop|NowMs|Cleanup> <artifact-root> <app> <cli> <receipt> <package-receipt> [arguments]" >&2
  exit 2
}

case "$MODE" in
  Reset|Bootstrap|InstallService|CreateAdmin|AdminAdd|ManualJoin|Verify|ReadMarker|ReadReceipt|ReadDaemonLog|Stop|NowMs|Cleanup) ;;
  *) usage ;;
esac
[[ "$ARTIFACT_ROOT" == /tmp/nvpn-linux-vm-release.*/* ]] || {
  echo "Linux desktop/mobile join requires the unique imported artifact root" >&2
  exit 2
}
[[ "$APP" == /usr/bin/nostr-vpn \
  && "$CLI" == /usr/bin/nvpn \
  && "$RECEIPT" == /tmp/nvpn-linux-vm-release.*/receipt.json \
  && "$PACKAGE_RECEIPT" == /tmp/nvpn-linux-vm-release.*/debian-package-install.json ]] || {
  echo "Linux desktop/mobile join requires exact DEB-installed executables" >&2
  exit 2
}
[[ -x "$APP" && ! -L "$APP" && -x "$CLI" && ! -L "$CLI" \
  && -f "$RECEIPT" && ! -L "$RECEIPT" \
  && -f "$PACKAGE_RECEIPT" && ! -L "$PACKAGE_RECEIPT" ]] || {
  echo "Linux desktop/mobile join imported artifact set is incomplete" >&2
  exit 2
}

MARKER="$ARTIFACT_ROOT/action.json"
STOP_PATH="$ARTIFACT_ROOT/stop"
DRIVER="$ROOT/scripts/desktop-mobile-manual-join-atspi.py"
SERVICE_BINARY=/usr/local/bin/nvpn
SERVICE_UNIT=/etc/systemd/system/nvpn.service
CONFIG="${XDG_DATA_HOME:-$HOME/.local/share}/nostr-vpn/config.toml"
PROFILE_ROOT="${CONFIG%/config.toml}"

assert_imported_artifacts() {
  local app_hash cli_hash
  app_hash="$(jq -er '.artifacts.app.sha256' "$RECEIPT")"
  cli_hash="$(jq -er '.artifacts.cli.sha256' "$RECEIPT")"
  [[ "$app_hash" =~ ^[0-9a-f]{64}$ \
    && "$cli_hash" =~ ^[0-9a-f]{64}$ \
    && "$(sha256sum "$APP" | awk '{ print $1 }')" == "$app_hash" \
    && "$(sha256sum "$CLI" | awk '{ print $1 }')" == "$cli_hash" \
    && "$(jq -er '.dockerPlatform' "$RECEIPT")" == linux/amd64 ]] || {
    echo "Linux desktop/mobile imported artifact receipt did not verify" >&2
    return 1
  }
  jq -e \
    --arg app "$APP" \
    --arg cli "$CLI" \
    --arg app_hash "$app_hash" \
    --arg cli_hash "$cli_hash" '
      .schema == 2
      and .package == "nostr-vpn"
      and .packageInstalledByDpkg == true
      and .installedStatus == "installed"
      and .installedAppPath == $app
      and .installedCliPath == $cli
      and .installedAppSha256 == $app_hash
      and .installedCliSha256 == $cli_hash
    ' "$PACKAGE_RECEIPT" >/dev/null || {
    echo "Linux desktop/mobile DEB install receipt did not verify" >&2
    return 1
  }
  jq -e '
    .schema == 2
    and (
      (
        .builderMode == "local-docker"
        and .builtOnHostMac == true
        and .builtOnRemoteVm == false
        and .builderHostOs == "Darwin"
        and (
          .builderHostArchitecture == "arm64"
          or .builderHostArchitecture == "x86_64"
        )
      )
      or (
        .builderMode == "remote-native"
        and .builtOnHostMac == false
        and .builtOnRemoteVm == true
        and .builderHostOs == "Linux"
        and .builderHostArchitecture == "x86_64"
      )
    )
    and (.containerImageId | test("^sha256:[0-9a-f]{64}$"))
    and (.dockerfileSha256 | test("^[0-9a-f]{64}$"))
    and (.containerPayloadSha256 | test("^[0-9a-f]{64}$"))
  ' "$RECEIPT" >/dev/null || {
    echo "Linux desktop/mobile imported builder provenance did not verify" >&2
    return 1
  }
}

assert_service_ready() {
  local expected_hash expected_version
  expected_hash="$(jq -er '.artifacts.cli.sha256' "$RECEIPT")"
  expected_version="$(jq -er '.appVersion' "$RECEIPT")"
  for _ in {1..75}; do
    if "$CLI" service status --json --config "$CONFIG" 2>/dev/null \
      | jq -e --arg version "$expected_version" '
      select(.running and .label == "nvpn.service" and .binary_path == "/usr/local/bin/nvpn"
        and .binary_version == $version and (.pid | type == "number" and . > 1))
    ' >/dev/null \
      && [[ "$(sudo -n sha256sum "$SERVICE_BINARY" | awk '{ print $1 }')" == "$expected_hash" ]]; then
      return 0
    fi
    sleep 0.2
  done
  echo "Linux desktop/mobile join exact daemon did not become ready" >&2
  return 1
}

cleanup_candidate_service() {
  local expected_hash has_binary=0 has_unit=0
  expected_hash="$(jq -er '.artifacts.cli.sha256' "$RECEIPT")"
  if sudo -n test -e "$SERVICE_BINARY" || sudo -n test -L "$SERVICE_BINARY"; then
    has_binary=1
    if ! sudo -n test -f "$SERVICE_BINARY" || sudo -n test -L "$SERVICE_BINARY" \
      || [[ "$(sudo -n sha256sum "$SERVICE_BINARY" | awk '{ print $1 }')" != "$expected_hash" ]]; then
      echo "Refusing to remove a service binary outside this candidate" >&2
      return 1
    fi
  fi
  if sudo -n test -e "$SERVICE_UNIT" || sudo -n test -L "$SERVICE_UNIT"; then
    has_unit=1
    if ! sudo -n test -f "$SERVICE_UNIT" || sudo -n test -L "$SERVICE_UNIT" \
      || ! sudo -n grep -Fq \
        "ExecStart=\"$SERVICE_BINARY\" daemon --service --config \"$CONFIG\" " \
        "$SERVICE_UNIT"; then
      echo "Refusing to remove a service unit outside this candidate" >&2
      return 1
    fi
  fi
  if [[ "$has_binary" -eq 0 && "$has_unit" -eq 0 ]]; then
    if systemctl is-active --quiet nvpn.service; then
      echo "Refusing to stop an active service without candidate-owned files" >&2
      return 1
    fi
    return 0
  fi
  sudo -n "$CLI" service uninstall --config "$CONFIG" >/dev/null
  if [[ "$has_binary" -eq 1 ]]; then
    sudo -n find "$SERVICE_BINARY" -maxdepth 0 -type f -delete
  fi
  if systemctl is-active --quiet nvpn.service \
    || sudo -n test -e "$SERVICE_UNIT" \
    || sudo -n test -e "$SERVICE_BINARY"; then
    echo "Linux desktop/mobile join service cleanup did not complete" >&2
    return 1
  fi
}

cleanup_release_test_profile() {
  local expected="$HOME/.local/share/nostr-vpn"
  [[ "$PROFILE_ROOT" == "$expected" ]] || {
    echo "Refusing to remove a profile outside the dedicated release-test path" >&2
    return 1
  }
  if sudo -n test -e "$PROFILE_ROOT" || sudo -n test -L "$PROFILE_ROOT"; then
    if ! sudo -n test -d "$PROFILE_ROOT" || sudo -n test -L "$PROFILE_ROOT"; then
      echo "Refusing to remove a non-directory or symlinked release-test profile" >&2
      return 1
    fi
    sudo -n find "$PROFILE_ROOT" -xdev -depth -delete
  fi
  sudo -n test ! -e "$PROFILE_ROOT"
}

install_candidate_service() {
  assert_imported_artifacts
  [[ "$CONFIG" == /* && -f "$CONFIG" && ! -L "$CONFIG" ]] || {
    echo "Linux canonical profile was not bootstrapped before service installation" >&2; return 1
  }
  if [[ -e "$SERVICE_UNIT" || -L "$SERVICE_UNIT" \
    || -e "$SERVICE_BINARY" || -L "$SERVICE_BINARY" ]] \
    || systemctl is-active --quiet nvpn.service; then
    echo "Linux desktop/mobile join requires an empty service slot" >&2; return 1
  fi
  if sudo -n "$CLI" service install --force --config "$CONFIG" \
    && assert_service_ready; then
    echo "LINUX_RELEASE_MOBILE_JOIN_SERVICE_READY"
    return 0
  fi
  cleanup_candidate_service
  return 1
}

write_stop_atomically() {
  mkdir -p "$ARTIFACT_ROOT"
  local temporary="$ARTIFACT_ROOT/.stop.$$.tmp"
  printf 'stop\n' >"$temporary"
  mv -f "$temporary" "$STOP_PATH"
}

run_driver() {
  local action="$1"
  shift
  assert_imported_artifacts
  [[ -x "$DRIVER" ]] || {
    echo "Linux desktop/mobile AT-SPI driver is missing" >&2
    return 1
  }
  mkdir -p "$ARTIFACT_ROOT"
  rm -f "$MARKER" "$STOP_PATH"
  env -u NVPN_APP_DATA_DIR -u NVPN_CLI_PATH \
    GTK_A11Y=atspi \
    NO_AT_BRIDGE=0 \
    GDK_BACKEND=x11 \
    xvfb-run -a dbus-run-session -- \
    python3 "$DRIVER" "$action" \
      --app "$APP" \
      --marker "$MARKER" \
      --artifact-root "$ARTIFACT_ROOT" \
      --stop-path "$STOP_PATH" \
      "$@"
  python3 - "$MARKER" "$action" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
value = json.loads(path.read_text(encoding="utf-8"))
required = {
    "schema": 1,
    "mode": sys.argv[2],
    "publicUiOnly": True,
    "privateStateRead": False,
    "appLaunchArgumentsOrEnvironment": False,
}
for key, expected in required.items():
    if value.get(key) != expected:
        raise SystemExit(f"Linux public UI marker lacks {key}={expected!r}")
PY
}

case "$MODE" in
  Reset)
    [[ $# == 0 ]] || usage
    run_driver Reset
    ;;
  Bootstrap)
    [[ $# == 0 ]] || usage
    run_driver Bootstrap
    ;;
  InstallService)
    [[ $# == 0 ]] || usage
    install_candidate_service
    ;;
  CreateAdmin)
    [[ $# == 1 ]] || usage
    run_driver CreateAdmin --network-name "$1"
    ;;
  AdminAdd)
    [[ $# == 2 ]] || usage
    run_driver AdminAdd \
      --participant-npub "$1" \
      --participant-alias "$2"
    ;;
  ManualJoin)
    [[ $# == 2 ]] || usage
    run_driver ManualJoin --admin-npub "$1" --network-id "$2"
    ;;
  Verify)
    [[ $# == 1 ]] || usage
    run_driver Verify --participant-npub "$1"
    ;;
  ReadMarker)
    [[ $# == 0 && -f "$MARKER" && ! -L "$MARKER" ]] || exit 1
    cat "$MARKER"
    ;;
  ReadReceipt)
    [[ $# == 0 ]] || usage
    assert_imported_artifacts
    cat "$RECEIPT"
    ;;
  ReadDaemonLog)
    [[ $# == 0 ]] || usage
    log="$HOME/.local/state/nvpn/daemon.log"
    [[ -f "$log" && ! -L "$log" ]] || exit 1
    cat "$log"
    ;;
  Stop)
    [[ $# == 0 ]] || usage
    write_stop_atomically
    ;;
  NowMs)
    [[ $# == 0 ]] || usage
    python3 - <<'PY'
import time
print(time.time_ns() // 1_000_000)
PY
    ;;
  Cleanup)
    (( $# <= 1 )) || usage
    pkill -u "$(id -u)" -x nostr-vpn >/dev/null 2>&1 || true
    rm -f "$STOP_PATH"
    if [[ "${1:-0}" != 0 ]]; then
      cleanup_candidate_service
      cleanup_release_test_profile
    fi
    ;;
esac
