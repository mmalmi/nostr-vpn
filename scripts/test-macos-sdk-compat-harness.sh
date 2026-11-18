#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SOURCE="$ROOT_DIR/macos/Sources/QRCodeScannerView.swift"
CHECK="$ROOT_DIR/scripts/check-macos-swift-sdk-compat.sh"
WORKFLOW="$ROOT_DIR/.github/workflows/release.yml"

fail() {
  echo "macOS SDK compatibility harness failed: $*" >&2
  exit 1
}

guarded_source="$(sed -n '/#if compiler(>=6\.2)/,/#endif/p' "$SOURCE")"
[[ "$(grep -Fc 'isCinematicVideoCaptureEnabled = false' "$SOURCE")" == "1" ]] \
  || fail "expected exactly one Cinematic Video safeguard"
grep -Fq 'if #available(macOS 26.0, *)' <<<"$guarded_source" \
  || fail "macOS 26 runtime availability check is outside the compiler guard"
grep -Fq 'isCinematicVideoCaptureEnabled = false' <<<"$guarded_source" \
  || fail "Cinematic Video safeguard is outside the Swift 6.2 compiler guard"

grep -Fq 'xcrun swiftc' "$CHECK" || fail "compatibility check does not invoke swiftc"
grep -Fq -- '-typecheck' "$CHECK" || fail "compatibility check does not type-check"
grep -Fq 'QRCodeScannerView.swift' "$CHECK" || fail "compatibility check omits scanner source"
grep -Fq '/Applications/Xcode_16.0.app/Contents/Developer' "$WORKFLOW" \
  || fail "release workflow does not pin the compatibility check to Xcode 16.0"
grep -Fq 'run: ./scripts/check-macos-swift-sdk-compat.sh' "$WORKFLOW" \
  || fail "release workflow does not run the compatibility check"

if [[ "$(uname -s)" == "Darwin" ]]; then
  "$CHECK"
fi

echo "macOS SDK compatibility harness passed"
