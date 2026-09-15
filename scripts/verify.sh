#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# Avoid the retired machine-wide target even when a long-lived shell still
# exports it. An explicit non-legacy target remains supported.
if [[ "${CARGO_TARGET_DIR:-}" == "$HOME/.cache/cargo-target" ]]; then
  unset CARGO_TARGET_DIR
fi
if command -v sccache >/dev/null 2>&1; then
  export SCCACHE_BASEDIRS="${SCCACHE_BASEDIRS:-$ROOT}"
fi

usage() {
  cat >&2 <<'EOF'
usage: scripts/verify.sh fast|full|health

fast   Per-change Rust/core/contract checks without native GUI or devices.
full   Fast checks plus the reserved five-platform and physical-device matrix.
health Preflight the full matrix without running tests.
EOF
}

run_fast() {
  python3 scripts/test-native-lab.py
  node scripts/sync-versions.mjs --check
  cargo fmt --check -p nvpn -p nostr-vpn-app-core -p nostr-vpn-core -p nostr-vpn-sim -p nostr-vpn-web -p nostr-vpn-wintun -p nostr-vpn-uniffi-bindgen
  cargo clippy --workspace --exclude nvpn-cashu-service --exclude nvpn-cdk-spilman --all-targets -- -D warnings
  # mobile-test-kit runs all app-core tests below, including app-state.
  scripts/test-dataplane-safety-fast.sh nvpn
  scripts/mobile-test-kit.sh rust
  scripts/test-mobile-platform-tools.sh
}

build_health_args() {
  HEALTH_ARGS=(
    --health local:macos
    --health command:xcrun
    --health command:xcodebuild
    --health command:adb
    --health docker:daemon
    --health command:ssh
    --health env:NVPN_WINDOWS_SSH_HOST
    --health "ios-simulator:${NVPN_LAB_IOS_SIMULATOR:-auto}"
    --health "ios-device:${NVPN_LAB_IOS_DEVICE:-auto}"
    --health "android:${NVPN_LAB_ANDROID_SERIAL:-auto}"
  )
  if [[ -n "${NVPN_WINDOWS_SSH_HOST:-}" ]]; then
    HEALTH_ARGS+=(--health "ssh:${NVPN_WINDOWS_SSH_HOST}")
  fi
  ALLOCATION_ARGS=(
    --allocation-env ios-simulator=NVPN_LAB_ALLOCATED_IOS_SIMULATOR
    --allocation-env ios-device=NVPN_LAB_ALLOCATED_IOS_DEVICE
    --allocation-env android=NVPN_LAB_ALLOCATED_ANDROID
  )
}

run_full() {
  build_health_args
  result="${NVPN_VERIFY_RESULT:-$ROOT/artifacts/verification/full-native-result.json}"
  python3 scripts/native-lab.py run \
    --resource nostr-vpn-five-platform-native-matrix \
    --result "$result" \
    "${HEALTH_ARGS[@]}" \
    "${ALLOCATION_ARGS[@]}" \
    -- scripts/verify-full-native.sh
}

case "${1:-}" in
  fast)
    run_fast
    ;;
  full)
    if [[ "${NVPN_VERIFY_SKIP_FAST:-0}" != "1" ]]; then
      run_fast
    fi
    run_full
    ;;
  health)
    build_health_args
    python3 scripts/native-lab.py health "${HEALTH_ARGS[@]}"
    ;;
  *)
    usage
    exit 2
    ;;
esac
