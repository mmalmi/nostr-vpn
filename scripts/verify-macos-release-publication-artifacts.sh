#!/usr/bin/env bash
set -euo pipefail

if (($# < 7 || $# > 8)); then
  echo "usage: $0 RECEIPT APP UPDATER_TAR DMG COMMIT TREE VALIDATOR [HOSTED_ADMISSION]" >&2
  exit 2
fi

RECEIPT="$1"
APP="$2"
UPDATER="$3"
DMG="$4"
COMMIT="$5"
TREE="$6"
VALIDATOR="$7"
admission_args=()
if [[ -n "${8:-}" ]]; then
  admission_args=(--hosted-admission "$8")
fi

updater_root="$(mktemp -d "${TMPDIR:-/tmp}/nvpn-macos-updater-proof.XXXXXX")"
mount_root="$(mktemp -d "${TMPDIR:-/tmp}/nvpn-macos-dmg-proof.XXXXXX")"
attached=0

cleanup() {
  local status=$?
  if ((attached)); then
    hdiutil detach "$mount_root" >/dev/null || status=1
  fi
  rm -rf "$updater_root" "$mount_root"
  exit "$status"
}
trap cleanup EXIT

verify_app() {
  python3 "$VALIDATOR" validate-published-app \
    --receipt "$RECEIPT" \
    --app "$1" \
    --expected-app-head "$COMMIT" \
    --expected-app-tree "$TREE" "${admission_args[@]}"
}

verify_app "$APP"

tar -xzpf "$UPDATER" -C "$updater_root"
verify_app "$updater_root/Nostr VPN.app"

hdiutil attach -readonly -nobrowse -mountpoint "$mount_root" "$DMG"
attached=1
verify_app "$mount_root/Nostr VPN.app"
hdiutil detach "$mount_root"
attached=0
