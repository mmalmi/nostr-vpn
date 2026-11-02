#!/usr/bin/env bash

set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/nvpn-ios-generated-project.XXXXXX")"
trap 'rm -rf "$TMP_DIR"' EXIT

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "Skipping generated iOS project check on this non-Apple host."
  exit 0
fi
if ! command -v xcodegen >/dev/null 2>&1; then
  echo "Generated iOS project check requires xcodegen." >&2
  exit 1
fi

# shellcheck disable=SC1091
source "$ROOT/scripts/release_common.sh"
resolve_ios_build_metadata "$ROOT"
export NVPN_IOS_BUNDLE_ID="${NVPN_IOS_BUNDLE_ID:-${NVPN_DEFAULT_IOS_BUNDLE_ID:-fi.siriusbusiness.nvpn}}"
export NVPN_IOS_PACKET_TUNNEL_BUNDLE_ID="${NVPN_IOS_PACKET_TUNNEL_BUNDLE_ID:-$NVPN_IOS_BUNDLE_ID.PacketTunnel}"
export NVPN_IOS_APP_GROUP_IDENTIFIER="${NVPN_IOS_APP_GROUP_IDENTIFIER:-group.$NVPN_IOS_BUNDLE_ID.shared}"

mkdir -p "$TMP_DIR/ios/Frameworks"
cp "$ROOT/ios/project.yml" "$TMP_DIR/ios/project.yml"
cp -R \
  "$ROOT/ios/Sources" \
  "$ROOT/ios/PacketTunnel" \
  "$ROOT/ios/Shared" \
  "$ROOT/ios/ShareFiles" \
  "$ROOT/ios/UITests" \
  "$ROOT/ios/Resources" \
  "$TMP_DIR/ios/"

xcodegen generate \
  --spec "$TMP_DIR/ios/project.yml" \
  --quiet

generated="$TMP_DIR/ios/NostrVpnIos.xcodeproj/project.pbxproj"
# Keep the comparison identical to tools/run-ios project generation.
perl -0pi -e 's/objectVersion = 77;/objectVersion = 56;/' "$generated"

if ! cmp -s "$ROOT/ios/NostrVpnIos.xcodeproj/project.pbxproj" "$generated"; then
  echo "Tracked iOS project differs from deterministic project.yml output." >&2
  diff -u "$ROOT/ios/NostrVpnIos.xcodeproj/project.pbxproj" "$generated" >&2 || true
  exit 1
fi

echo "Tracked iOS project matches deterministic project.yml output."
