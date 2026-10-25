#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
./scripts/macos-build macos-xcframework
TARGET="${NVPN_MACOS_HOST_TARGET:-$(rustc -vV | awk '/host:/ {print $2}')}"
PROFILE="${NVPN_MACOS_RUST_PROFILE:-debug}"
TARGET_DIR="${NVPN_MACOS_CARGO_TARGET_DIR:-$ROOT/macos/.build/cargo-target}"
[[ "$TARGET_DIR" = /* ]] || TARGET_DIR="$ROOT/$TARGET_DIR"
LIB_DIR="$TARGET_DIR/$TARGET/$PROFILE"
TEST_DIR="$(mktemp -d "${TMPDIR:-/tmp}/nvpn-update-test.XXXXXX")"
trap 'rm -rf "$TEST_DIR"' EXIT

sources=()
for source in macos/Sources/*.swift; do
  [[ "$source" == */NostrVpnMacApp.swift ]] || sources+=("$source")
done
xcrun swiftc -D DEBUG -parse-as-library \
  -I macos/Bindings \
  -Xcc -fmodule-map-file=macos/Bindings/NostrVpnAppCoreFFI.modulemap \
  "${sources[@]}" macos/Bindings/NostrVpnAppCore.swift \
  macos/Tests/UpdateRecoveryTests.swift \
  -L "$LIB_DIR" -lnostr_vpn_app_core \
  -Xlinker -rpath -Xlinker "$LIB_DIR" \
  -framework SystemConfiguration -framework Security \
  -o "$TEST_DIR/update-recovery"
NVPN_MACOS_FIXTURE_MODE=1 "$TEST_DIR/update-recovery" "$@"
