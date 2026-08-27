#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "$ROOT/scripts/local-fips-workspace.sh"

usage() {
  cat >&2 <<'EOF'
usage: scripts/mobile-test-kit.sh [rust|fast|simulator|device|exit]

Modes:
  rust       Run shared Rust mobile/core tests only.
  fast       Run Rust tests plus Android and iOS debug builds.
  simulator  Run fast checks, then iOS simulator and Android adb launch smokes.
  device     Run opt-in local physical-device VPN/TUN smokes.
  exit       Run physical Android/iOS WireGuard exit, DNS, and Direct restore e2e.

Device identifiers are intentionally not stored in the repo. Use environment
variables such as NVPN_ANDROID_SERIAL and NVPN_IOS_DEVICE when needed, or copy
.env.mobile.example to .env.mobile.local for local ignored values. Device mode
builds and installs the exact current iOS app with company Ad Hoc signing by
default, then exercises the local Packet Tunnel without a private enrollment
fixture.
Android --vpn-cycle validates the app-private Rust runtime-state file after the
OS VPN network becomes active; tune with NVPN_ANDROID_RUNTIME_STATE_WAIT_SECS
or NVPN_ANDROID_RUNTIME_STATE_MAX_AGE_SECS if a slow device needs it. It also
requires tunPacketsRead to increase after a small shell ping burst; disable only
for device images without ping via NVPN_ANDROID_TUN_PACKET_PROBE=0. The Android
artifacts include normalized ping, TUN packet, and VPN link-counter summaries.

Set NVPN_FIPS_REPO_PATH=/path/to/fips when testing mobile Rust code against
unreleased local FIPS crates. Cargo.toml and Cargo.lock are restored after
local-FIPS cargo runs so platform iteration does not leave workspace churn
behind.

Simulator mode verifies app build/install/launch. Real VPN dataplane checks
need physical devices. Device mode uses debug-created local networks for OS
VPN/TUN coverage without private peer fixtures: Android may tap the system VPN
consent prompt on a trusted local test device. The iOS run requires local
signing credentials; set NVPN_IOS_DEVICE_SIGNING_MODE=development only for
Xcode-managed development signing.
EOF
}

fail() {
  printf 'mobile test kit failed: %s\n' "$*" >&2
  exit 1
}

cargo_test() {
  nvpn_prepare_local_fips_workspace "$ROOT"
  (cd "$ROOT" && cargo test "$@")
}

run_rust() {
  cargo_test -p nostr-vpn-app-core
  cargo_test -p nvpn platform_routing
}

run_android_build() {
  "$ROOT/tools/run-android" build
}

run_ios_build() {
  if [[ "$(uname -s)" != "Darwin" ]]; then
    echo "Skipping iOS build on non-Darwin host"
    return
  fi
  "$ROOT/tools/run-ios" build
}

run_fast() {
  run_rust
  run_android_build
  run_ios_build
}

mode="${1:-fast}"
case "$mode" in
  rust)
    run_rust
    ;;
  fast)
    run_fast
    ;;
  simulator|sim)
    run_fast
    "$ROOT/scripts/mobile-ios-smoke.sh" simulator
    "$ROOT/scripts/mobile-android-smoke.sh" --no-build
    ;;
  device)
    "$ROOT/scripts/mobile-android-smoke.sh" --create-network --accept-vpn-dialog --vpn-cycle
    "$ROOT/scripts/mobile-ios-smoke.sh" device --install --create-network --vpn-cycle
    ;;
  exit)
    "$ROOT/scripts/mobile-wireguard-exit-e2e.sh" all
    ;;
  -h|--help|help)
    usage
    ;;
  *)
    usage
    exit 2
    ;;
esac
