#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT/scripts/lib-mobile-wireguard-fixture.sh"
TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/nvpn-wg-staging-harness.XXXXXX")"
STATE="$(mktemp -d /var/tmp/nvpn-mobile-wg-exit.staging-harness.XXXXXX)"
trap 'rm -rf "$TMP_ROOT" "$STATE" "${STATE}.link"' EXIT

# Exercise the real initializer with transport-only mocks; no SSH or host changes.
for selected in default /var/tmp; do
  (
    source "$ROOT/scripts/lib-mobile-wireguard-fixture.sh"
    export NVPN_MOBILE_WG_EXIT_FIXTURE_SSH_HOST=fixture
    export NVPN_MOBILE_WG_EXIT_HOST_IP=192.0.2.1
    if [[ "$selected" == default ]]; then
      unset NVPN_MOBILE_WG_EXIT_REMOTE_TEMP_ROOT
      expected=/tmp
    else
      export NVPN_MOBILE_WG_EXIT_REMOTE_TEMP_ROOT="$selected"
      expected="$selected"
    fi
    mobile_wg_remote_exec() { [[ "$*" != "uname -s" ]] || printf 'Linux\n'; }
    mobile_wg_remote_has_command() { return 0; }
    scp() { return 0; }
    HOST_PORT=53000
    mobile_wg_fixture_initialize "$ROOT" "$TMP_ROOT"
    [[ "$MOBILE_WG_FIXTURE_REMOTE_DIR" == "$expected/nvpn-mobile-wg-exit.port-53000" ]]
  )
done

for selected in / /var/tmp/ /var/tmp/../tmp '/var/tmp;touch bad'; do
  (
    export NVPN_MOBILE_WG_EXIT_FIXTURE_SSH_HOST=fixture
    export NVPN_MOBILE_WG_EXIT_REMOTE_TEMP_ROOT="$selected"
    mobile_wg_remote_exec() { touch "$TMP_ROOT/unexpected-transport"; return 0; }
    if mobile_wg_fixture_initialize "$ROOT" "$TMP_ROOT" >/dev/null 2>&1; then exit 1; fi
    [[ ! -e "$TMP_ROOT/unexpected-transport" ]]
  )
done

for unsafe in /var/tmp /var/tmp/nvpn-mobile-wg-exit.x/../foreign /etc/nvpn-mobile-wg-exit.x; do
  (
    MOBILE_WG_FIXTURE_REMOTE_DIR="$unsafe"
    mobile_wg_remote_exec() { touch "$TMP_ROOT/unexpected-cleanup"; return 0; }
    mobile_wg_remote_close_control() { :; }
    if mobile_wg_fixture_cleanup fixture image >/dev/null 2>&1; then exit 1; fi
    if mobile_wg_fixture_recover_inactive_remote_dir; then exit 1; fi
    [[ ! -e "$TMP_ROOT/unexpected-cleanup" ]]
  )
done

ln -s "$STATE" "${STATE}.link"
mkdir "$STATE/fixture"
for path in "$STATE" "$STATE/fixture"; do
  env NVPN_MOBILE_WG_REMOTE_STATE_DIR="$path" NVPN_MOBILE_WG_REMOTE_INTERFACE=nwg53000 \
    NVPN_MOBILE_WG_REMOTE_NFT_TABLE=nvpnwg53000 bash -c 'helper=$1; set --; source "$helper"' \
    bash "$ROOT/scripts/mobile-wireguard-exit-remote-native.sh"
done
for path in "${STATE}.link" "${STATE}.link/fixture" "$STATE/../foreign"; do
  if env NVPN_MOBILE_WG_REMOTE_STATE_DIR="$path" NVPN_MOBILE_WG_REMOTE_INTERFACE=nwg53000 \
      NVPN_MOBILE_WG_REMOTE_NFT_TABLE=nvpnwg53000 bash "$ROOT/scripts/mobile-wireguard-exit-remote-native.sh" \
      >/dev/null 2>&1; then exit 1; fi
done
printf 'WireGuard fixture staging paths and unsafe-path cleanup checks passed\n'
