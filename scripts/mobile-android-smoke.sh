#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "$ROOT/scripts/release_common.sh"
# shellcheck disable=SC1091
source "$ROOT/scripts/mobile_env.sh"
# shellcheck disable=SC1091
source "$ROOT/scripts/lib-mobile-underlay-change.sh"
# shellcheck disable=SC1091
source "$ROOT/scripts/lib-mobile-android-underlay.sh"
# shellcheck disable=SC1091
source "$ROOT/scripts/lib-mobile-android-external-probe.sh"
# shellcheck disable=SC1091
source "$ROOT/scripts/lib-mobile-android-release-gate.sh"
load_release_env "$ROOT"
# The canonical debug candidate must replace the installed release-signed app
# in place. Keep the signing values in the ignored local Zapstore env.
load_env_file_defaults "$ROOT/.env.zapstore.local"
load_mobile_env "$ROOT"
resolve_shared_build_metadata "$ROOT"
CANONICAL_PACKAGE_NAME="${NVPN_DEFAULT_APP_ID:-fi.siriusbusiness.nvpn}"
LEGACY_PACKAGE_NAME="${NVPN_ANDROID_LEGACY_PACKAGE:-org.nostrvpn.app}"
PACKAGE_NAME="${NVPN_ANDROID_PACKAGE:-$CANONICAL_PACKAGE_NAME}"
ACTION_PACKAGE_NAME="${NVPN_ANDROID_ACTION_PACKAGE:-$CANONICAL_PACKAGE_NAME}"
if [[ "$PACKAGE_NAME" == "$CANONICAL_PACKAGE_NAME" \
  && -n "${ANDROID_KEYSTORE_PATH:-}" \
  && -n "${ANDROID_KEYSTORE_PASSWORD:-}" \
  && -n "${ANDROID_KEY_ALIAS:-}" \
  && -n "${ANDROID_KEY_PASSWORD:-}" ]]
then
  # A physical candidate must update the installed canonical release in place.
  # Use the same key instead of creating an incompatible debug-signed APK.
  export NVPN_ANDROID_DEBUG_RELEASE_SIGNING=1
fi
MAIN_ACTIVITY="${NVPN_ANDROID_ACTIVITY:-$PACKAGE_NAME/org.nostrvpn.app.MainActivity}"
DEBUG_ACTION_EXTRA="${NVPN_ANDROID_DEBUG_ACTION_EXTRA:-$ACTION_PACKAGE_NAME.DEBUG_ACTION}"
DEBUG_EXIT_NODE_EXTRA="${NVPN_ANDROID_DEBUG_EXIT_NODE_EXTRA:-$ACTION_PACKAGE_NAME.DEBUG_EXIT_NODE}"
DEBUG_NETWORK_NAME_EXTRA="${NVPN_ANDROID_DEBUG_NETWORK_NAME_EXTRA:-$ACTION_PACKAGE_NAME.DEBUG_NETWORK_NAME}"
DEBUG_WIREGUARD_CONFIG_BASE64_EXTRA="${NVPN_ANDROID_DEBUG_WIREGUARD_CONFIG_BASE64_EXTRA:-$ACTION_PACKAGE_NAME.DEBUG_WIREGUARD_CONFIG_BASE64}"
DEBUG_EXIT_DNS_PATCH_BASE64_EXTRA="${NVPN_ANDROID_DEBUG_EXIT_DNS_PATCH_BASE64_EXTRA:-$ACTION_PACKAGE_NAME.DEBUG_EXIT_DNS_PATCH_BASE64}"
DEBUG_NETWORK_PROBE_BASE64_EXTRA="${NVPN_ANDROID_DEBUG_NETWORK_PROBE_BASE64_EXTRA:-$ACTION_PACKAGE_NAME.DEBUG_NETWORK_PROBE_BASE64}"
RELEASE_BLACKBOX_GATE="${NVPN_ANDROID_RELEASE_BLACKBOX_GATE:-0}"
case "$RELEASE_BLACKBOX_GATE" in
  1|true|TRUE|True|yes|YES|Yes)
    APK_PATH="${NVPN_ANDROID_APK:-$ROOT/android/app/build/outputs/apk/release/app-release.apk}"
    ;;
  *)
    APK_PATH="${NVPN_ANDROID_APK:-$ROOT/android/app/build/outputs/apk/debug/app-debug.apk}"
    ;;
esac
VPN_START_WAIT_SECS="${NVPN_ANDROID_VPN_START_WAIT_SECS:-15}"
VPN_STOP_WAIT_SECS="${NVPN_ANDROID_VPN_STOP_WAIT_SECS:-10}"
RUNTIME_STATE_WAIT_SECS="${NVPN_ANDROID_RUNTIME_STATE_WAIT_SECS:-12}"
RUNTIME_STATE_MAX_AGE_SECS="${NVPN_ANDROID_RUNTIME_STATE_MAX_AGE_SECS:-60}"
RUNTIME_STATE_RESULT_DIR="${NVPN_ANDROID_RESULT_DIR:-$ROOT/artifacts/mobile-android}"
RUNTIME_STATE_RESULT_NAME="${NVPN_ANDROID_RUNTIME_STATE_RESULT_NAME:-mobile-android-runtime-state-$$.json}"
ANDROID_BUILD_METADATA_RESULT_NAME="${NVPN_ANDROID_BUILD_METADATA_RESULT_NAME:-mobile-android-build-metadata-$$.json}"
ANDROID_IDLE_CPU_RESULT_NAME="${NVPN_ANDROID_IDLE_CPU_RESULT_NAME:-mobile-android-idle-cpu-$$.json}"
ANDROID_IDLE_CPU_OUTPUT="${NVPN_ANDROID_IDLE_CPU_OUTPUT:-}"
VPN_LINK_STATS_RESULT_NAME="mobile-android-vpn-link-stats-$$.txt"
VPN_LINK_STATS_SUMMARY_RESULT_NAME="mobile-android-vpn-link-stats-summary-$$.tsv"
PING_PROBE_RESULT_NAME="mobile-android-ping-probe-$$.txt"
PING_PROBE_SUMMARY_RESULT_NAME="mobile-android-ping-probe-summary-$$.json"
TUN_PACKET_PROBE_SUMMARY_RESULT_NAME="mobile-android-tun-probe-summary-$$.json"
TUN_PACKET_PROBE="${NVPN_ANDROID_TUN_PACKET_PROBE:-1}"
TUN_PACKET_PROBE_TARGET="${NVPN_ANDROID_TUN_PACKET_PROBE_TARGET:-10.44.255.254}"
TUN_PACKET_PROBE_COUNT="${NVPN_ANDROID_TUN_PACKET_PROBE_COUNT:-4}"
TUN_PACKET_PROBE_WAIT_SECS="${NVPN_ANDROID_TUN_PACKET_PROBE_WAIT_SECS:-15}"
TUN_PACKET_PROBE_TIMEOUT_SECS="${NVPN_ANDROID_TUN_PACKET_PROBE_TIMEOUT_SECS:-1}"
TUN_PACKET_PROBE_REQUIRE_REPLY="${NVPN_ANDROID_TUN_PACKET_PROBE_REQUIRE_REPLY:-0}"
EXIT_PROBE_HOST="${NVPN_ANDROID_EXIT_PROBE_HOST:-}"
EXIT_PROBE_EXPECTED_IP="${NVPN_ANDROID_EXIT_PROBE_EXPECTED_IP:-}"
DIRECT_PROBE_HOST="${NVPN_ANDROID_DIRECT_PROBE_HOST:-example.com}"
DIRECT_PROBE_URL="${NVPN_ANDROID_DIRECT_PROBE_URL:-https://example.com/}"
EXIT_PROBE_URL="${NVPN_ANDROID_EXIT_PROBE_URL:-https://example.com/}"
CAPTURED_PROBE_URL="${NVPN_ANDROID_CAPTURED_PROBE_URL:-}"
CAPTURED_PROBE_TOKEN="${NVPN_ANDROID_CAPTURED_PROBE_TOKEN:-}"
EXIT_SOURCE_PROBE_URL="${NVPN_ANDROID_EXIT_SOURCE_PROBE_URL:-}"
EXPECTED_EXIT_SOURCE_IP="${NVPN_ANDROID_EXPECTED_EXIT_SOURCE_IP:-}"
DIRECT_RESTORE_WAIT_SECS="${NVPN_ANDROID_DIRECT_RESTORE_WAIT_SECS:-20}"
EXPECTED_VPN_DNS="${NVPN_ANDROID_EXPECTED_VPN_DNS:-10.44.0.53}"
EXPECTED_WIREGUARD_ENDPOINT="${NVPN_ANDROID_EXPECT_WIREGUARD_ENDPOINT:-}"
EXPECTED_FIPS_GIT_SHA="${NVPN_EXPECTED_FIPS_GIT_SHA:-}"
DEBUG_SEED_WAIT_SECS="${NVPN_ANDROID_DEBUG_SEED_WAIT_SECS:-10}"
DEBUG_EXIT_NODE="${NVPN_ANDROID_DEBUG_EXIT_NODE:-}"
DEBUG_WIREGUARD_CONFIG="${NVPN_ANDROID_DEBUG_WIREGUARD_CONFIG:-}"
DEBUG_WIREGUARD_CONFIG_FILE="${NVPN_ANDROID_DEBUG_WIREGUARD_CONFIG_FILE:-}"
RELEASE_WIREGUARD_CONFIG="${NVPN_ANDROID_WIREGUARD_CONFIG:-}"
RELEASE_WIREGUARD_CONFIG_FILE="${NVPN_ANDROID_WIREGUARD_CONFIG_FILE:-}"
EXIT_DNS_MODE="${NVPN_ANDROID_EXIT_DNS_MODE:-}"
EXIT_DNS_DOH_PROVIDER="${NVPN_ANDROID_EXIT_DNS_DOH_PROVIDER:-cloudflare}"
EXIT_DNS_CUSTOM_DOH_URL="${NVPN_ANDROID_EXIT_DNS_CUSTOM_DOH_URL:-}"
EXIT_DNS_CUSTOM_DOH_BOOTSTRAP_IPS="${NVPN_ANDROID_EXIT_DNS_CUSTOM_DOH_BOOTSTRAP_IPS:-}"
EXIT_DNS_THROUGH_EXIT_SERVERS="${NVPN_ANDROID_EXIT_DNS_THROUGH_EXIT_SERVERS:-}"
EXIT_DNS_USE_SHIPPED_UI="${NVPN_ANDROID_EXIT_DNS_USE_SHIPPED_UI:-0}"
ANDROID_UI_WAIT_SECS="${NVPN_ANDROID_UI_WAIT_SECS:-15}"
SWITCH_TO_DIRECT_WHILE_CONNECTED="${NVPN_ANDROID_SWITCH_TO_DIRECT_WHILE_CONNECTED:-0}"
EXIT_DNS_RESULT_FILE="debug-exit-dns-state.json"
EXIT_DNS_RESULT_NAME="mobile-android-exit-dns-state-$$.json"
NETWORK_PROBE_RESULT_FILE="debug-network-probe.json"
DEBUG_NETWORK_NAME="${NVPN_ANDROID_DEBUG_NETWORK_NAME:-Android smoke}"
cleanup_after_vpn_cycle="${NVPN_ANDROID_CLEANUP_AFTER_VPN_CYCLE:-1}"
IDLE_CPU_GATE="${NVPN_ANDROID_IDLE_CPU_GATE:-${NVPN_IDLE_CPU_GATE:-1}}"
IDLE_CPU_MAX_PERCENT="${NVPN_ANDROID_IDLE_CPU_MAX_PERCENT:-${NVPN_IDLE_CPU_MAX_PERCENT:-5}}"
IDLE_CPU_SAMPLE_SECONDS="${NVPN_ANDROID_IDLE_CPU_SAMPLE_SECONDS:-${NVPN_IDLE_CPU_SAMPLE_SECONDS:-10}}"
IDLE_CPU_SETTLE_SECONDS="${NVPN_ANDROID_IDLE_CPU_SETTLE_SECONDS:-${NVPN_IDLE_CPU_SETTLE_SECONDS:-3}}"
ANDROID_LIFECYCLE_GATE="${NVPN_ANDROID_LIFECYCLE_GATE:-1}"
ANDROID_LIFECYCLE_CYCLES="${NVPN_ANDROID_LIFECYCLE_CYCLES:-3}"
ANDROID_LIFECYCLE_BACKGROUND_DWELL_SECS="${NVPN_ANDROID_LIFECYCLE_BACKGROUND_DWELL_SECS:-10}"
ANDROID_RAPID_START_STOP_GATE="${NVPN_ANDROID_RAPID_START_STOP_GATE:-0}"
ANDROID_RELEASE_DNS_ONLY_CYCLE="${NVPN_ANDROID_RELEASE_DNS_ONLY_CYCLE:-0}"

build=1
install=1
clear_state=0
create_network="${NVPN_ANDROID_DEBUG_CREATE_NETWORK:-0}"
accept_vpn_dialog="${NVPN_ANDROID_ACCEPT_VPN_DIALOG:-0}"
vpn_cycle=0
serial="${NVPN_ANDROID_SERIAL:-${ANDROID_SERIAL:-}}"
PACKAGE_UID=""
vpn_cleanup_armed=0
DIRECT_UNDERLYING_DNS_BASELINE=""
ANDROID_CAPTURED_PROBE_BUILD_DIR=""
ANDROID_CAPTURED_PROBE_REMOTE_JAR=""

usage() {
  cat >&2 <<'EOF'
usage: scripts/mobile-android-smoke.sh [--release-network-gate] [--no-build] [--no-install] [--clear] [--vpn-cycle] [--create-network] [--accept-vpn-dialog] [--leave-vpn-active] [--serial SERIAL] [--probe-target IP] [--probe-count N] [--probe-timeout SECS] [--probe-require-reply] [--no-tun-probe]

Builds and installs the debug APK, launches the app through adb, and optionally
cycles the debug VPN action. Values may live in .env.mobile.local, shell env,
or --serial. Keep device identifiers and signing details out of committed files.
The installed debug app must report build metadata matching this repo checkout.
Every smoke backgrounds and foregrounds the Activity and requires the same app
process to survive and resume.

--release-network-gate builds and installs the company-signed Release APK, then
uses only shipped UI controls plus external OS/device traffic probes. Debug
actions, app-sandbox reads, config seeding, and synthetic app probe actions are
forbidden in this mode.

NVPN_ANDROID_RELEASE_REUSE_VERIFIED_ARTIFACT=1 permits a focused Release retry
without rebuilding or reinstalling only when both --no-build and --no-install
are present and the sealed APK, AAB, schema-2 receipt, and physical-gate
relationship receipt all validate exactly.

First-run Android VPN permission prompts may need manual approval before
--vpn-cycle can run unattended.

For fresh installs, --vpn-cycle needs an active nvpn network. Use
--create-network for local OS VPN/TUN coverage, or approve the device's signed
join request from an admin device before running peer dataplane coverage.

Use --create-network for a local OS VPN/TUN smoke when peer dataplane coverage is
not required. It creates a debug-only local network named by
NVPN_ANDROID_DEBUG_NETWORK_NAME, then cycles the VPN.

Use --accept-vpn-dialog only on trusted local test devices; it taps Android's
system VPN consent OK button if the prompt appears.

When --vpn-cycle reaches Android's active VPN service/network state, this script
also copies files/app-core/mobile-runtime-state.json from the debug app sandbox
and requires fresh Rust runtime state with native TUN counter fields. It also
captures Android's own VPN interface counters from `ip -s link` or
`/proc/net/dev` under artifacts/mobile-android, plus normalized link-counter
summary rows.

By default --vpn-cycle also sends a small shell ping probe toward a non-local
10.44/16 address and requires tunPacketsRead to increase by at least the probe
count. The ping output is saved under artifacts/mobile-android so physical peer
targets preserve loss/jitter evidence; a separate TUN counter summary JSON records
the native packet observation. Use --probe-target with --probe-require-reply for
a reachable peer row that requires ping replies plus native TUN write counters.
Disable with --no-tun-probe if a device image lacks ping.

When NVPN_ANDROID_EXIT_PROBE_HOST is set, the cycle additionally proves a full
Direct -> WireGuard exit -> Direct transition. The named host must resolve only
through the fixture/profile DNS; NVPN_ANDROID_EXIT_PROBE_EXPECTED_IP pins its
answer. Public DNS and HTTPS are checked before connect, while the exit is
active, again after active-tunnel background/foreground cycles, and after
disconnect. The Android VPN network must advertise the local authenticated DNS
stub (10.44.0.53 by default).

Set NVPN_ANDROID_EXIT_DNS_MODE and its provider/custom/through-exit companion
variables to configure Exit DNS before connecting.
NVPN_ANDROID_EXIT_DNS_USE_SHIPPED_UI=1 requires the physical smoke to tap and
type through the shipped Compose controls, exercise required-field validation,
save, and verify config.toml persistence before the functional DNS probe.
The active exit lifecycle gate defaults to three background/foreground cycles
with at least ten seconds backgrounded and re-proves the real TUN, DNS policy,
configured WireGuard endpoint, and app-process HTTPS after every foreground.
NVPN_ANDROID_SWITCH_TO_DIRECT_WHILE_CONNECTED=1 then selects This device,
requires the Android VPN network to remain connected without a default route,
and proves DNS and Internet access in that state.

After a --vpn-cycle pass or failure, the script disconnects the debug VPN so
devices are left clean for the next smoke. Use --leave-vpn-active to preserve
the tunnel for explicit manual inspection.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --release-network-gate)
      RELEASE_BLACKBOX_GATE=1
      APK_PATH="${NVPN_ANDROID_APK:-$ROOT/android/app/build/outputs/apk/release/app-release.apk}"
      ;;
    --no-build)
      build=0
      ;;
    --no-install)
      install=0
      ;;
    --clear)
      clear_state=1
      ;;
    --create-network)
      create_network=1
      ;;
    --accept-vpn-dialog)
      accept_vpn_dialog=1
      ;;
    --leave-vpn-active)
      cleanup_after_vpn_cycle=0
      ;;
    --vpn-cycle)
      vpn_cycle=1
      ;;
    --serial)
      if [[ $# -lt 2 ]]; then
        echo "--serial requires a value" >&2
        exit 2
      fi
      serial="$2"
      shift
      ;;
    --probe-target)
      if [[ $# -lt 2 ]]; then
        echo "--probe-target requires a value" >&2
        exit 2
      fi
      TUN_PACKET_PROBE_TARGET="$2"
      shift
      ;;
    --probe-count)
      if [[ $# -lt 2 ]]; then
        echo "--probe-count requires a value" >&2
        exit 2
      fi
      TUN_PACKET_PROBE_COUNT="$2"
      shift
      ;;
    --probe-timeout)
      if [[ $# -lt 2 ]]; then
        echo "--probe-timeout requires a value" >&2
        exit 2
      fi
      TUN_PACKET_PROBE_TIMEOUT_SECS="$2"
      shift
      ;;
    --probe-require-reply)
      TUN_PACKET_PROBE_REQUIRE_REPLY=1
      ;;
    --no-tun-probe)
      TUN_PACKET_PROBE=0
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage
      exit 2
      ;;
  esac
  shift
done

sdk_from_local_properties() {
  local file="$ROOT/android/local.properties"
  if [[ -f "$file" ]]; then
    sed -n 's/^sdk\.dir=//p' "$file" | head -n 1
  fi
}

resolve_adb() {
  local sdk="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}"
  if [[ -z "$sdk" ]]; then
    sdk="$(sdk_from_local_properties)"
  fi
  if [[ -z "$sdk" && -d "$HOME/Library/Android/sdk" ]]; then
    sdk="$HOME/Library/Android/sdk"
  fi
  if [[ -n "$sdk" && -x "$sdk/platform-tools/adb" ]]; then
    printf '%s\n' "$sdk/platform-tools/adb"
    return
  fi
  if command -v adb >/dev/null 2>&1; then
    command -v adb
    return
  fi
  echo "adb not found; set ANDROID_HOME/ANDROID_SDK_ROOT or add adb to PATH" >&2
  exit 1
}

select_serial() {
  local adb="$1"
  if [[ -n "$serial" ]]; then
    printf '%s\n' "$serial"
    return
  fi
  "$adb" devices | awk '
    NR > 1 && $2 == "device" {
      if (first == "") first = $1
      if ($1 ~ /^emulator-/) {
        print $1
        selected = 1
        exit
      }
    }
    END { if (!selected && first != "") print first }
  '
}

resolve_package_uid() {
  local adb="$1"
  local target_serial="$2"
  "$adb" -s "$target_serial" shell cmd package list packages -U "$PACKAGE_NAME" \
    | tr -d '\r' \
    | awk -F '[: ]+' -v package="$PACKAGE_NAME" \
      '$1 == "package" && $2 == package && $3 == "uid" { print $4; exit }'
}

remove_stale_nvpn_packages() {
  local installed stale package remaining
  installed="$("$ADB" -s "$serial" shell pm list packages \
    | tr -d '\r' \
    | sed -n 's/^package://p')"
  stale="$(printf '%s\n' "$installed" \
    | awk -v canonical="$CANONICAL_PACKAGE_NAME" -v legacy="$LEGACY_PACKAGE_NAME" \
      '$0 == legacy || (index($0, canonical ".") == 1 && $0 != canonical)')"
  if android_release_reuse_verified_artifact; then
    [[ -z "$stale" ]] && grep -Fxq "$CANONICAL_PACKAGE_NAME" <<<"$installed" || {
      echo "Android verified-artifact reuse requires only canonical package $CANONICAL_PACKAGE_NAME" >&2
      return 1
    }
    return 0
  fi
  while IFS= read -r package; do
    [[ -n "$package" ]] || continue
    "$ADB" -s "$serial" shell am force-stop "$package" >/dev/null 2>&1 || true
    "$ADB" -s "$serial" uninstall "$package" >/dev/null \
      || { echo "Could not remove stale nVPN package $package" >&2; return 1; }
  done <<<"$stale"
  remaining="$("$ADB" -s "$serial" shell pm list packages \
    | tr -d '\r' \
    | sed -n 's/^package://p' \
    | awk -v canonical="$CANONICAL_PACKAGE_NAME" -v legacy="$LEGACY_PACKAGE_NAME" \
      '$0 == legacy || (index($0, canonical ".") == 1 && $0 != canonical)')"
  [[ -z "$remaining" ]] \
    || { echo "Stale parallel nVPN packages remain: $remaining" >&2; return 1; }
}

vpn_service_running() {
  local services
  services="$("$ADB" -s "$serial" shell dumpsys activity services "$PACKAGE_NAME" 2>/dev/null | tr -d '\r')" || return 1
  awk '
    /ServiceRecord\{.*NostrVpnService/ {
      in_service = 1
      next
    }
    in_service && /^[[:space:]]*\* ServiceRecord/ {
      in_service = 0
    }
    in_service && /app=/ {
      if ($0 !~ /app=null/) found = 1
      in_service = 0
    }
    END { exit found ? 0 : 1 }
  ' <<<"$services"
}

vpn_network_active() {
  local connectivity
  connectivity="$("$ADB" -s "$serial" shell dumpsys connectivity 2>/dev/null | tr -d '\r')" || return 1
  grep -F 'ni{VPN CONNECTED' <<<"$connectivity" \
    | grep -Fq "OwnerUid: $PACKAGE_UID"
}

vpn_active() {
  vpn_service_running && vpn_network_active
}

vpn_state_present() {
  vpn_service_running || vpn_network_active
}

wait_until() {
  local timeout="$1"
  shift
  local start now
  start="$(date +%s)"
  while true; do
    if "$@"; then
      return 0
    fi
    now="$(date +%s)"
    if (( now - start >= timeout )); then
      return 1
    fi
    sleep 1
  done
}

vpn_inactive() {
  ! vpn_state_present
}

truthy() {
  [[ "$1" == "1" || "$1" == "true" || "$1" == "yes" ]]
}

if android_release_reuse_verified_artifact \
  && ! truthy "$RELEASE_BLACKBOX_GATE"
then
  echo "Android verified-artifact reuse requires --release-network-gate" >&2
  exit 2
fi

epoch_ms() {
  python3 -c 'import time; print(int(time.time() * 1000))'
}

android_runtime_state_path() {
  printf '%s/%s\n' "$RUNTIME_STATE_RESULT_DIR" "$RUNTIME_STATE_RESULT_NAME"
}

android_build_metadata_path() {
  printf '%s/%s\n' "$RUNTIME_STATE_RESULT_DIR" "$ANDROID_BUILD_METADATA_RESULT_NAME"
}

android_idle_cpu_path() {
  if [[ -n "$ANDROID_IDLE_CPU_OUTPUT" ]]; then
    printf '%s\n' "$ANDROID_IDLE_CPU_OUTPUT"
    return
  fi
  printf '%s/%s\n' "$RUNTIME_STATE_RESULT_DIR" "$ANDROID_IDLE_CPU_RESULT_NAME"
}

run_android_idle_cpu_gate() {
  local label="$1"
  case "$IDLE_CPU_GATE" in
    0|false|FALSE|False|no|NO|No|off|OFF|Off)
      echo "Skipping Android idle CPU gate because NVPN_ANDROID_IDLE_CPU_GATE=$IDLE_CPU_GATE"
      return
      ;;
  esac
  mkdir -p "$(dirname "$(android_idle_cpu_path)")"
  "$ROOT/scripts/idle-cpu-gate.py" android-package \
    --adb "$ADB" \
    --serial "$serial" \
    --package "$PACKAGE_NAME" \
    --label "$label" \
    --artifact "$(android_idle_cpu_path)" \
    --max-percent "$IDLE_CPU_MAX_PERCENT" \
    --sample-seconds "$IDLE_CPU_SAMPLE_SECONDS" \
    --settle-seconds "$IDLE_CPU_SETTLE_SECONDS"
}

android_vpn_link_stats_path() {
  printf '%s/%s\n' "$RUNTIME_STATE_RESULT_DIR" "$VPN_LINK_STATS_RESULT_NAME"
}

android_vpn_link_stats_summary_path() {
  printf '%s/%s\n' "$RUNTIME_STATE_RESULT_DIR" "$VPN_LINK_STATS_SUMMARY_RESULT_NAME"
}

android_ping_probe_path() {
  printf '%s/%s\n' "$RUNTIME_STATE_RESULT_DIR" "$PING_PROBE_RESULT_NAME"
}

android_ping_probe_summary_path() {
  printf '%s/%s\n' "$RUNTIME_STATE_RESULT_DIR" "$PING_PROBE_SUMMARY_RESULT_NAME"
}

android_tun_packet_probe_summary_path() {
  printf '%s/%s\n' "$RUNTIME_STATE_RESULT_DIR" "$TUN_PACKET_PROBE_SUMMARY_RESULT_NAME"
}

android_network_probe_path() {
  local label="$1"
  printf '%s/mobile-android-network-%s-%s.txt\n' "$RUNTIME_STATE_RESULT_DIR" "$label" "$$"
}

android_app_network_probe_path() {
  local label="$1"
  printf '%s/mobile-android-app-network-%s-%s.json\n' "$RUNTIME_STATE_RESULT_DIR" "$label" "$$"
}

android_vpn_dns_servers() {
  "$ADB" -s "$serial" shell dumpsys connectivity 2>/dev/null \
    | tr -d '\r' \
    | python3 -c '
import re
import sys

text = sys.stdin.read()
owner = sys.argv[1]
for block in re.split(r"(?=NetworkAgentInfo\{)", text):
    if "ni{VPN CONNECTED" not in block or f"OwnerUid: {owner}" not in block:
        continue
    match = re.search(r"DnsAddresses:\s*\[([^]]*)\]", block)
    if not match:
        sys.exit(1)
    for value in re.findall(r"/?([0-9a-fA-F:.]+)", match.group(1)):
        print(value)
    sys.exit(0)
sys.exit(1)
' "$PACKAGE_UID"
}

android_validated_underlying_dns_servers() {
  "$ADB" -s "$serial" shell dumpsys connectivity 2>/dev/null \
    | tr -d '\r' \
    | python3 -c '
import re
import sys

text = sys.stdin.read()
for block in re.split(r"(?=NetworkAgentInfo\{)", text):
    if "NOT_VPN" not in block or "VALIDATED" not in block:
        continue
    if not re.search(r"(?<![0-9.])0\.0\.0\.0/0(?![0-9])|(?<!\S)::/0", block):
        continue
    match = re.search(r"DnsAddresses:\s*\[([^]]*)\]", block)
    if not match:
        continue
    values = sorted(set(re.findall(r"/?([0-9a-fA-F:.]+)", match.group(1))))
    if values:
        print("\n".join(values))
        sys.exit(0)
sys.exit(1)
'
}

android_vpn_has_default_route() {
  "$ADB" -s "$serial" shell dumpsys connectivity 2>/dev/null \
    | tr -d '\r' \
    | python3 -c '
import re
import sys

text = sys.stdin.read()
owner = sys.argv[1]
for block in re.split(r"(?=NetworkAgentInfo\{)", text):
    if "ni{VPN CONNECTED" not in block or f"OwnerUid: {owner}" not in block:
        continue
    owned_default = re.search(
        r"(?<![0-9.])0\.0\.0\.0/0(?![0-9])\s+(?!throw\b|unreachable\b)",
        block,
    ) or re.search(
        r"(?<!\S)::/0\s+(?!throw\b|unreachable\b)",
        block,
    )
    sys.exit(0 if owned_default else 1)
sys.exit(2)
' "$PACKAGE_UID"
}

run_android_app_network_probe() {
  local label="$1"
  local host="$2"
  local url="$3"
  local expected_ip="$4"
  local probe_id payload encoded result_path start now validation_error
  probe_id="$label-$$-$(date +%s%N)"
  payload="$(
    python3 - "$probe_id" "$host" "$url" <<'PY'
import json
import sys

probe_id, host, url = sys.argv[1:]
print(json.dumps(
    {"probeId": probe_id, "host": host, "url": url},
    separators=(",", ":"),
))
PY
  )"
  encoded="$(printf '%s' "$payload" | base64_no_wrap)"
  result_path="$(android_app_network_probe_path "$label")"
  mkdir -p "$RUNTIME_STATE_RESULT_DIR"
  "$ADB" -s "$serial" shell run-as "$PACKAGE_NAME" \
    rm -f "files/app-core/$NETWORK_PROBE_RESULT_FILE"
  start_main_activity \
    --es "$DEBUG_ACTION_EXTRA" network_probe \
    --es "$DEBUG_NETWORK_PROBE_BASE64_EXTRA" "$encoded"

  start="$(date +%s)"
  validation_error=""
  while true; do
    if "$ADB" -s "$serial" exec-out run-as "$PACKAGE_NAME" \
      cat "files/app-core/$NETWORK_PROBE_RESULT_FILE" >"$result_path.tmp" 2>/dev/null \
      && [[ -s "$result_path.tmp" ]]
    then
      if validation_error="$(
        python3 - "$result_path.tmp" "$probe_id" "$host" "$url" "$expected_ip" <<'PY'
import json
import sys

path, probe_id, host, url, expected_ip = sys.argv[1:]
try:
    with open(path, encoding="utf-8") as handle:
        result = json.load(handle)
except (OSError, json.JSONDecodeError) as error:
    print(f"receipt is not complete JSON: {error}")
    raise SystemExit(1)

errors = []
for key, expected in (("probeId", probe_id), ("host", host), ("url", url)):
    if result.get(key) != expected:
        errors.append(f"{key}={result.get(key)!r} expected={expected!r}")
addresses = result.get("resolvedAddresses")
if not isinstance(addresses, list) or not addresses:
    errors.append(f"resolvedAddresses={addresses!r}")
elif expected_ip and expected_ip not in addresses:
    errors.append(f"resolvedAddresses={addresses!r} expected to contain {expected_ip!r}")
status = result.get("statusCode")
if not isinstance(status, int) or not 200 <= status < 400:
    errors.append(f"statusCode={status!r}")
for key in ("error", "resolveError", "fetchError"):
    if result.get(key):
        errors.append(f"{key}={result[key]!r}")
if errors:
    print("Android app network probe invalid: " + ", ".join(errors))
    raise SystemExit(1)
PY
      )"
      then
        mv "$result_path.tmp" "$result_path"
        echo "Android VPN-excluded app-process $label native DNS/HTTPS safety probe passed: $result_path"
        return 0
      fi
    fi
    rm -f "$result_path.tmp"
    now="$(date +%s)"
    if (( now - start >= RUNTIME_STATE_WAIT_SECS )); then
      echo "Android app-process $label DNS/HTTPS probe failed: ${validation_error:-receipt missing}" >&2
      return 1
    fi
    sleep 1
  done
}

run_android_direct_network_probe() {
  local label="$1" result_path start now attempt always_on_app lockdown
  [[ -n "$EXIT_PROBE_HOST" ]] || return 0
  result_path="$(android_network_probe_path "$label")"
  mkdir -p "$RUNTIME_STATE_RESULT_DIR"
  if vpn_state_present; then
    echo "Android $label Direct probe failed: VPN state is still present" >&2
    return 1
  fi
  if [[ "$label" == "before-connect" ]]; then
    DIRECT_UNDERLYING_DNS_BASELINE="$(android_validated_underlying_dns_servers)" || {
      echo "Android before-connect Direct probe could not identify validated device DNS" >&2
      return 1
    }
  fi
  always_on_app="$("$ADB" -s "$serial" shell settings get secure always_on_vpn_app 2>/dev/null | tr -d '\r')"
  lockdown="$("$ADB" -s "$serial" shell settings get secure always_on_vpn_lockdown 2>/dev/null | tr -d '\r')"
  if [[ -n "$always_on_app" && "$always_on_app" != "null" && "$lockdown" == "1" ]]; then
    echo "Android $label Direct probe cannot run while system always-on VPN lockdown is enabled for $always_on_app" >&2
    return 1
  fi
  start="$(date +%s)"
  attempt=0
  : >"$result_path"
  while true; do
    attempt=$((attempt + 1))
    {
      printf 'label=%s attempt=%s elapsed=%ss host=%s\n' \
        "$label" "$attempt" "$(( $(date +%s) - start ))" "$DIRECT_PROBE_HOST"
      "$ADB" -s "$serial" shell ping -c 2 -W 3 "$DIRECT_PROBE_HOST"
    } >>"$result_path" 2>&1 && {
      if ! run_android_app_network_probe \
        "$label" \
        "$DIRECT_PROBE_HOST" \
        "$DIRECT_PROBE_URL" \
        ""
      then
        return 1
      fi
      echo "Android $label Direct DNS/Internet probe passed after $(( $(date +%s) - start ))s: $result_path"
      return 0
    }
    now="$(date +%s)"
    if (( now - start >= DIRECT_RESTORE_WAIT_SECS )); then
      echo "Android $label Direct DNS/Internet probe failed after $((now - start))s: $result_path" >&2
      return 1
    fi
    sleep 1
  done
}

run_android_exit_network_probe() {
  local label="${1:-wireguard-exit}"
  [[ -n "$EXIT_PROBE_HOST" ]] || return 0
  local dns_servers result_path resolved_ip secure_dns_before
  secure_dns_before=""
  if [[ "$EXIT_DNS_MODE" == "encrypted" ]]; then
    copy_android_runtime_state
    secure_dns_before="$(android_runtime_state_number secureDnsSuccesses)"
  fi
  result_path="$(android_network_probe_path "$label")"
  mkdir -p "$RUNTIME_STATE_RESULT_DIR"
  if ! dns_servers="$(android_vpn_dns_servers)"; then
    echo "Android WireGuard exit probe failed: active VPN DNS servers were unavailable" >&2
    return 1
  fi
  if ! grep -Fxq "$EXPECTED_VPN_DNS" <<<"$dns_servers"; then
    echo "Android WireGuard exit probe failed: VPN DNS is '$dns_servers', expected local stub $EXPECTED_VPN_DNS" >&2
    return 1
  fi
  {
    printf 'vpnDnsServers=%s\n' "$(tr '\n' ',' <<<"$dns_servers" | sed 's/,$//')"
    printf 'exitHost=%s\n' "$EXIT_PROBE_HOST"
    "$ADB" -s "$serial" shell ping -c 3 -W 3 "$EXIT_PROBE_HOST"
    printf 'publicHost=%s\n' "$DIRECT_PROBE_HOST"
    "$ADB" -s "$serial" shell ping -c 2 -W 3 "$DIRECT_PROBE_HOST"
  } >"$result_path" 2>&1 || {
    echo "Android WireGuard exit DNS/Internet probe failed: $result_path" >&2
    return 1
  }
  resolved_ip="$(sed -n 's/^PING [^(]*(\([^)]*\)).*/\1/p' "$result_path" | head -n 1)"
  if [[ -n "$EXIT_PROBE_EXPECTED_IP" && "$resolved_ip" != "$EXIT_PROBE_EXPECTED_IP" ]]; then
    echo "Android WireGuard exit DNS resolved $EXIT_PROBE_HOST to '$resolved_ip', expected $EXIT_PROBE_EXPECTED_IP: $result_path" >&2
    return 1
  fi
  if [[ "$EXIT_DNS_MODE" == "encrypted" ]]; then
    if ! wait_for_secure_dns_success_after "$secure_dns_before"; then
      return 1
    fi
  fi
  if ! run_android_captured_network_probe "$label"; then
    return 1
  fi
  if ! run_android_app_network_probe \
    "$label-vpn-excluded-safety" \
    "$DIRECT_PROBE_HOST" \
    "$DIRECT_PROBE_URL" \
    ""
  then
    return 1
  fi
  if ! android_exit_dns_persisted; then
    echo "Android $label probe failed: WireGuard endpoint or Exit DNS policy changed" >&2
    return 1
  fi
  echo "Android WireGuard exit captured DNS/HTTP/HTTPS and exact policy passed after $label: $result_path DNS=$EXPECTED_VPN_DNS answer=$resolved_ip endpoint=${EXPECTED_WIREGUARD_ENDPOINT:-configured}"
}

wait_for_secure_dns_success_after() {
  local baseline="$1"
  local start now current
  [[ "$baseline" =~ ^[0-9]+$ ]] || {
    echo "Android encrypted DNS probe has no baseline success counter" >&2
    return 1
  }
  start="$(date +%s)"
  while true; do
    if copy_android_runtime_state; then
      current="$(android_runtime_state_number secureDnsSuccesses 2>/dev/null || true)"
      if [[ "$current" =~ ^[0-9]+$ ]] && (( current > baseline )); then
        echo "Android production encrypted-DNS resolver passed: successes=$baseline->$current"
        return 0
      fi
    fi
    now="$(date +%s)"
    if (( now - start >= RUNTIME_STATE_WAIT_SECS )); then
      echo "Android encrypted-DNS resolver did not record a successful authenticated DoH response (baseline=$baseline current=${current:-missing})" >&2
      return 1
    fi
    sleep 1
  done
}

android_exit_dns_result_path() {
  printf '%s/%s\n' "$RUNTIME_STATE_RESULT_DIR" "$EXIT_DNS_RESULT_NAME"
}

android_ui_vpn_toggle_checked() {
  local remote="/sdcard/nvpn-ui-vpn-toggle.xml"
  local xml status=0
  xml="$(mktemp)"
  if ! "$ADB" -s "$serial" shell uiautomator dump "$remote" >/dev/null 2>&1 \
    || ! "$ADB" -s "$serial" pull "$remote" "$xml" >/dev/null 2>&1
  then
    rm -f "$xml"
    return 1
  fi
  python3 - "$xml" <<'PY' || status="$?"
import html
import re
import sys

raw = open(sys.argv[1], encoding="utf-8").read()
descriptions = {
    html.unescape(value)
    for value in re.findall(r'content-desc="([^"]*)"', raw)
}
turn_off = "Turn VPN off" in descriptions
turn_on = "Turn VPN on" in descriptions
if turn_off == turn_on:
    raise SystemExit(1)
print("true" if turn_off else "false")
PY
  rm -f "$xml"
  return "$status"
}

android_ui_query() {
  local selector_type="$1"
  local selector="$2"
  local attribute="$3"
  local remote="/sdcard/nvpn-ui-smoke.xml"
  local xml status=0
  xml="$(mktemp)"
  if ! "$ADB" -s "$serial" shell uiautomator dump "$remote" >/dev/null 2>&1 \
    || ! "$ADB" -s "$serial" pull "$remote" "$xml" >/dev/null 2>&1
  then
    rm -f "$xml"
    return 1
  fi
  if [[ "$attribute" == "visible-center" ]]; then
    "$ROOT/scripts/mobile-release-join-ui-query.py" \
      "$xml" "$selector_type" "$selector" visible-center || status="$?"
    rm -f "$xml"
    return "$status"
  fi
  python3 - "$xml" "$selector_type" "$selector" "$attribute" <<'PY' || status="$?"
import html
import re
import sys

path, selector_type, selector, attribute = sys.argv[1:]
raw = open(path, encoding="utf-8").read()
nodes = [
    dict(
        (name, html.unescape(value))
        for name, value in re.findall(r'([a-z-]+)="([^"]*)"', node)
    )
    for node in re.findall(r"<node [^>]+>", raw)
]

def bounds(attributes):
    match = re.fullmatch(
        r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]",
        attributes.get("bounds", ""),
    )
    return tuple(map(int, match.groups())) if match else None

for attributes in nodes:
    if selector_type == "resource":
        matches = attributes.get("resource-id") == selector
    elif selector_type == "description":
        matches = attributes.get("content-desc") == selector
    else:
        raise SystemExit(f"unknown Android UI selector type: {selector_type}")
    if not matches:
        continue
    if attribute in ("center", "safe-center"):
        bounds = re.fullmatch(
            r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]",
            attributes.get("bounds", ""),
        )
        if not bounds:
            continue
        left, top, right, bottom = map(int, bounds.groups())
        if right <= left or bottom <= top:
            continue
        if attribute == "safe-center":
            screen = re.search(
                r'<node [^>]*bounds="\[0,0\]\[(\d+),(\d+)\]"',
                raw,
            )
            screen_bottom = int(screen.group(2)) if screen else 2400
            if top < 200 or bottom > screen_bottom - 300:
                continue
        print((left + right) // 2, (top + bottom) // 2)
    elif attribute == "descendant-text":
        parent = bounds(attributes)
        if parent is None:
            continue
        left, top, right, bottom = parent
        values = []
        for child in nodes:
            value = child.get("text", "")
            child_bounds = bounds(child)
            if not value or child_bounds is None:
                continue
            child_left, child_top, child_right, child_bottom = child_bounds
            if (
                child_left >= left
                and child_top >= top
                and child_right <= right
                and child_bottom <= bottom
            ):
                values.append(value)
        if len(values) != 1:
            continue
        print(values[0])
    elif attribute == "selected":
        print(
            "true"
            if attributes.get("selected") == "true"
            or attributes.get("checked") == "true"
            else "false"
        )
    else:
        print(attributes.get(attribute, ""))
    raise SystemExit(0)
raise SystemExit(1)
PY
  rm -f "$xml"
  return "$status"
}

android_ui_swipe() {
  local direction="$1"
  local size width height start_y end_y
  size="$("$ADB" -s "$serial" shell wm size \
    | tr -d '\r' \
    | awk -F': ' '/Physical size:/ { print $2; exit }')"
  width="${size%x*}"
  height="${size#*x}"
  if [[ ! "$width" =~ ^[0-9]+$ || ! "$height" =~ ^[0-9]+$ ]]; then
    width=1080
    height=2400
  fi
  if [[ "$direction" == "up" ]]; then
    start_y="$((height * 4 / 5))"
    end_y="$((height / 3))"
  else
    start_y="$((height / 3))"
    end_y="$((height * 4 / 5))"
  fi
  "$ADB" -s "$serial" shell input swipe \
    "$((width / 2))" "$start_y" "$((width / 2))" "$end_y" 250
}

android_ui_reset_scroll() {
  local ignored
  for ignored in 1 2 3 4 5 6; do
    android_ui_swipe down >/dev/null
  done
}

android_ui_scroll_to() {
  local selector_type="$1"
  local selector="$2"
  local ignored
  for ignored in 1 2 3 4 5 6 7 8 9 10 11 12; do
    if android_ui_query "$selector_type" "$selector" safe-center >/dev/null; then
      return 0
    fi
    android_ui_swipe up >/dev/null
  done
  android_ui_query "$selector_type" "$selector" safe-center >/dev/null
}

tap_android_ui() {
  local selector_type="$1"
  local selector="$2"
  local point
  point="$(android_ui_query "$selector_type" "$selector" center)" || return 1
  # shellcheck disable=SC2086
  "$ADB" -s "$serial" shell input tap $point
}

tap_android_ui_visible() {
  local selector_type="$1"
  local selector="$2"
  local ignored point
  for ignored in 1 2 3 4 5 6 7 8 9 10 11 12; do
    if point="$(
      android_ui_query "$selector_type" "$selector" visible-center
    )"; then
      # shellcheck disable=SC2086
      "$ADB" -s "$serial" shell input tap $point
      return
    fi
    android_ui_swipe up >/dev/null
  done
  return 1
}

wait_for_android_ui() {
  local selector_type="$1"
  local selector="$2"
  local deadline=$((SECONDS + ANDROID_UI_WAIT_SECS))
  while ((SECONDS < deadline)); do
    if android_ui_query "$selector_type" "$selector" center >/dev/null; then
      return 0
    fi
    sleep 0.25
  done
  return 1
}

android_capture_internet_navigation_failure() {
  local context="$1" remote="/sdcard/nvpn-ui-navigation-failure.xml"
  local slug result
  slug="$(tr -cs '[:alnum:]' '-' <<<"$context" | sed 's/^-//; s/-$//')"
  result="$RUNTIME_STATE_RESULT_DIR/mobile-android-${slug:-internet}-navigation-$$.xml"
  mkdir -p "$RUNTIME_STATE_RESULT_DIR"
  if "$ADB" -s "$serial" shell uiautomator dump "$remote" >/dev/null 2>&1 \
    && "$ADB" -s "$serial" pull "$remote" "$result" >/dev/null 2>&1
  then
    echo "Android $context UI state saved for diagnosis: $result" >&2
  else
    echo "Android $context UI state could not be captured" >&2
  fi
}

android_open_internet_settings_ui() {
  local context="${1:-Internet configuration}"
  start_main_activity || {
    echo "Android $context could not launch the shipped app" >&2
    return 1
  }
  wait_until 5 android_activity_resumed || {
    echo "Android $context did not resume the shipped MainActivity" >&2
    android_capture_internet_navigation_failure "$context"
    return 1
  }
  if android_ui_query resource internet-source-picker center >/dev/null 2>&1; then
    return 0
  fi
  wait_for_android_ui description "Internet tab" || {
    echo "Android $context could not find the Internet tab in the shipped app shell" >&2
    android_capture_internet_navigation_failure "$context"
    return 1
  }
  tap_android_ui description "Internet tab" || {
    echo "Android $context could not tap the Internet tab" >&2
    android_capture_internet_navigation_failure "$context"
    return 1
  }
  android_ui_reset_scroll || {
    echo "Android $context could not reset the Internet settings scroll position" >&2
    android_capture_internet_navigation_failure "$context"
    return 1
  }
  wait_for_android_ui resource internet-source-picker || {
    echo "Android $context tapped the Internet tab but did not reach the Internet settings screen (missing internet-source-picker)" >&2
    android_capture_internet_navigation_failure "$context"
    return 1
  }
}

replace_android_ui_text() {
  local selector="$1"
  local value="$2"
  android_ui_scroll_to resource "$selector" || return 1
  tap_android_ui resource "$selector" || return 1
  local deadline=$((SECONDS + 3))
  while ((SECONDS < deadline)); do
    if [[ "$(android_ui_query resource "$selector" focused 2>/dev/null || true)" == "true" ]]; then
      break
    fi
    sleep 0.25
  done
  if [[ "$(android_ui_query resource "$selector" focused 2>/dev/null || true)" != "true" ]]; then
    echo "Android shipped text field did not gain focus: $selector" >&2
    return 1
  fi
  "$ADB" -s "$serial" shell input keycombination -t 40 KEYCODE_CTRL_LEFT KEYCODE_A
  "$ADB" -s "$serial" shell input keyevent KEYCODE_DEL
  if [[ -n "$value" ]]; then
    "$ADB" -s "$serial" shell input text "${value// /%s}"
  fi
  "$ADB" -s "$serial" shell input keyevent KEYCODE_BACK
  sleep 0.25
  local actual
  actual="$(android_ui_query resource "$selector" text)" || return 1
  if [[ "$actual" != "$value" ]]; then
    echo "Android shipped text field entry mismatch: $selector" >&2
    return 1
  fi
}

replace_android_ui_multiline_text() {
  local selector="$1"
  local value="$2"
  local deadline
  tap_android_ui_visible resource "$selector" || return 1
  deadline=$((SECONDS + 3))
  while ((SECONDS < deadline)); do
    if [[ "$(android_ui_query resource "$selector" focused 2>/dev/null || true)" == "true" ]]; then
      break
    fi
    sleep 0.25
  done
  if [[ "$(android_ui_query resource "$selector" focused 2>/dev/null || true)" != "true" ]]; then
    echo "Android shipped multiline field did not gain focus: $selector" >&2
    return 1
  fi
  "$ADB" -s "$serial" shell input keycombination -t 40 KEYCODE_CTRL_LEFT KEYCODE_A
  "$ADB" -s "$serial" shell input keyevent KEYCODE_DEL
  local line first=1
  { set +x; } 2>/dev/null
  while IFS= read -r line || [[ -n "$line" ]]; do
    if [[ "$first" -eq 0 ]]; then
      # adb reads stdin even though `input` does not need it. Without this
      # redirect, the first invocation consumes the here-string and silently
      # truncates every multiline config after its first line.
      "$ADB" -s "$serial" shell input keyevent KEYCODE_ENTER </dev/null
    fi
    first=0
    if [[ -n "$line" ]]; then
      "$ADB" -s "$serial" shell input text "${line// /%s}" </dev/null
    fi
  done <<<"$value"
  "$ADB" -s "$serial" shell input keyevent KEYCODE_BACK
  sleep 0.5
  local actual
  actual="$(android_ui_query resource "$selector" text)" || return 1
  if [[ "${actual%$'\n'}" != "${value%$'\n'}" ]]; then
    echo "Android shipped multiline field entry mismatch: $selector" >&2
    return 1
  fi
}

assert_android_ui_validation() {
  local expected="$1"
  local description="Exit DNS validation error: $expected"
  android_ui_scroll_to description "$description" || {
    echo "Android shipped Exit DNS UI did not show validation: $expected" >&2
    return 1
  }
  local enabled
  android_ui_scroll_to resource exit-dns-save || return 1
  enabled="$(android_ui_query resource exit-dns-save enabled)" || return 1
  if [[ "$enabled" != "false" ]]; then
    echo "Android shipped Exit DNS Save remained enabled for: $expected" >&2
    return 1
  fi
}

assert_android_ui_save_enabled() {
  android_ui_scroll_to resource exit-dns-save || return 1
  local enabled
  enabled="$(android_ui_query resource exit-dns-save enabled)" || return 1
  if [[ "$enabled" != "true" ]]; then
    echo "Android shipped Exit DNS Save was disabled for valid settings" >&2
    return 1
  fi
}

android_exit_dns_persisted() {
  "$ADB" -s "$serial" exec-out run-as "$PACKAGE_NAME" \
    cat files/app-core/config.toml 2>/dev/null \
    | python3 -c '
import json
import re
import sys

mode, provider, custom_url, bootstrap, through, expected_endpoint = sys.argv[1:]
text = sys.stdin.read()


def section(name):
    match = re.search(
        rf"(?ms)^\[{re.escape(name)}\]\s*$\n(.*?)(?=^\[|\Z)",
        text,
    )
    return match.group(1) if match else ""


def scalar(body, key, default=""):
    match = re.search(
        rf"(?m)^\s*{re.escape(key)}\s*=\s*\"((?:\\.|[^\"])*)\"\s*$",
        body,
    )
    return json.loads(f"\"{match.group(1)}\"") if match else default


def boolean(body, key, default=False):
    match = re.search(
        rf"(?m)^\s*{re.escape(key)}\s*=\s*(true|false)\s*$",
        body,
    )
    return (match.group(1) == "true") if match else default


def array(body, key):
    match = re.search(
        rf"(?ms)^\s*{re.escape(key)}\s*=\s*\[(.*?)\]\s*$",
        body,
    )
    if not match:
        return []
    return [
        json.loads(f"\"{value}\"")
        for value in re.findall(r"\"((?:\\.|[^\"])*)\"", match.group(1))
    ]


top_level = re.split(r"(?m)^\[", text, maxsplit=1)[0]
dns = section("exit_dns")
wireguard = section("wireguard_exit")
if scalar(dns, "mode", "automatic") != mode:
    raise SystemExit(1)
if scalar(top_level, "internet_source") != "wire_guard":
    raise SystemExit(1)
if not boolean(wireguard, "enabled"):
    raise SystemExit(1)
if expected_endpoint and scalar(wireguard, "endpoint") != expected_endpoint:
    raise SystemExit(1)
if mode == "encrypted":
    if scalar(dns, "doh_provider", "cloudflare") != provider:
        raise SystemExit(1)
    if provider == "custom":
        expected_bootstrap = [value.strip() for value in bootstrap.split(",") if value.strip()]
        if scalar(dns, "custom_doh_url") != custom_url:
            raise SystemExit(1)
        if array(dns, "custom_doh_bootstrap_ips") != expected_bootstrap:
            raise SystemExit(1)
if mode == "through_exit":
    expected_servers = [value.strip() for value in through.split(",") if value.strip()]
    if array(dns, "through_exit_servers") != expected_servers:
        raise SystemExit(1)
' "$EXIT_DNS_MODE" "$EXIT_DNS_DOH_PROVIDER" \
      "$EXIT_DNS_CUSTOM_DOH_URL" "$EXIT_DNS_CUSTOM_DOH_BOOTSTRAP_IPS" \
      "$EXIT_DNS_THROUGH_EXIT_SERVERS" "$EXPECTED_WIREGUARD_ENDPOINT"
}

wait_for_android_exit_dns_persistence() {
  if truthy "$RELEASE_BLACKBOX_GATE"; then
    # Release APKs are non-debuggable, so the gate intentionally cannot read
    # their sandbox. The saved policy is proved by the subsequent external
    # resolver request and fixture-side DNS/DoH counters.
    sleep 1
    echo "Android Release Exit DNS save accepted through shipped UI: mode=$EXIT_DNS_MODE provider=$EXIT_DNS_DOH_PROVIDER"
    return 0
  fi
  local deadline=$((SECONDS + RUNTIME_STATE_WAIT_SECS))
  while ((SECONDS < deadline)); do
    if android_exit_dns_persisted; then
      echo "Android shipped Exit DNS UI persistence passed: mode=$EXIT_DNS_MODE provider=$EXIT_DNS_DOH_PROVIDER"
      return 0
    fi
    sleep 0.25
  done
  echo "Android shipped Exit DNS UI did not persist mode=$EXIT_DNS_MODE provider=$EXIT_DNS_DOH_PROVIDER" >&2
  return 1
}

write_android_exit_dns_ui_receipt() {
  local result_path
  result_path="$(android_exit_dns_result_path)"
  mkdir -p "$RUNTIME_STATE_RESULT_DIR"
  python3 - \
    "$result_path" \
    "$EXIT_DNS_MODE" \
    "$EXIT_DNS_DOH_PROVIDER" \
    "$EXIT_DNS_CUSTOM_DOH_URL" \
    "$EXIT_DNS_CUSTOM_DOH_BOOTSTRAP_IPS" \
    "$EXIT_DNS_THROUGH_EXIT_SERVERS" \
    "$RELEASE_BLACKBOX_GATE" <<'PY'
import json
import pathlib
import sys

(
    output,
    mode,
    provider,
    custom_url,
    bootstrap_ips,
    through_servers,
    release_blackbox,
) = sys.argv[1:]
payload = {
    "receiptSchema": 1,
    "evidenceSource": "shipped-ui-restart-readback",
    "uiRestartReadback": True,
    "releaseBlackbox": release_blackbox.lower()
    in {"1", "true", "yes", "on"},
    "exitDnsMode": mode,
    "exitDnsDohProvider": provider,
    "exitDnsCustomDohUrl": custom_url,
    "exitDnsCustomDohBootstrapIps": bootstrap_ips,
    "exitDnsThroughExitServers": through_servers,
    "internetSource": "wireguard",
    "wireguardExitEnabled": True,
    "error": "",
}
path = pathlib.Path(output)
temporary = path.with_name(f".{path.name}.tmp")
temporary.write_text(
    json.dumps(payload, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
temporary.replace(path)
PY
}

assert_android_exit_dns_ui_reloaded() {
  "$ADB" -s "$serial" shell am force-stop "$PACKAGE_NAME"
  android_open_internet_settings_ui "Exit DNS restart readback" || return 1
  android_ui_reset_scroll

  local source mode_selector selected
  android_ui_scroll_to resource internet-source-picker || return 1
  source="$(android_ui_query resource internet-source-picker descendant-text)" || return 1
  if [[ "$source" != "WireGuard VPN" ]]; then
    echo "Android Exit DNS restart readback lost WireGuard internet source: $source" >&2
    return 1
  fi
  assert_android_internet_status_contains "WireGuard" || return 1

  mode_selector="exit-dns-mode-$EXIT_DNS_MODE"
  android_ui_scroll_to resource "$mode_selector" || return 1
  selected="$(android_ui_query resource "$mode_selector" selected)" || return 1
  if [[ "$selected" != "true" ]]; then
    echo "Android Exit DNS restart readback lost mode=$EXIT_DNS_MODE" >&2
    return 1
  fi

  if [[ "$EXIT_DNS_MODE" == "encrypted" ]]; then
    local provider_selector
    provider_selector="exit-dns-provider-$EXIT_DNS_DOH_PROVIDER"
    android_ui_scroll_to resource "$provider_selector" || return 1
    selected="$(android_ui_query resource "$provider_selector" selected)" || return 1
    if [[ "$selected" != "true" ]]; then
      echo "Android Exit DNS restart readback lost provider=$EXIT_DNS_DOH_PROVIDER" >&2
      return 1
    fi
    if [[ "$EXIT_DNS_DOH_PROVIDER" == "custom" ]]; then
      android_ui_scroll_to resource exit-dns-custom-url || return 1
      [[ "$(android_ui_query resource exit-dns-custom-url text)" == "$EXIT_DNS_CUSTOM_DOH_URL" ]] \
        || {
          echo "Android Exit DNS restart readback lost the custom DoH URL" >&2
          return 1
        }
      android_ui_scroll_to resource exit-dns-custom-bootstrap-ips || return 1
      [[ "$(android_ui_query resource exit-dns-custom-bootstrap-ips text)" == "$EXIT_DNS_CUSTOM_DOH_BOOTSTRAP_IPS" ]] \
        || {
          echo "Android Exit DNS restart readback lost custom bootstrap IPs" >&2
          return 1
        }
    fi
  elif [[ "$EXIT_DNS_MODE" == "through_exit" ]]; then
    android_ui_scroll_to resource exit-dns-through-exit-servers || return 1
    [[ "$(android_ui_query resource exit-dns-through-exit-servers text)" == "$EXIT_DNS_THROUGH_EXIT_SERVERS" ]] \
      || {
        echo "Android Exit DNS restart readback lost through-exit DNS servers" >&2
        return 1
      }
  fi

  write_android_exit_dns_ui_receipt || return 1
  echo "Android shipped Exit DNS restart readback passed: mode=$EXIT_DNS_MODE provider=$EXIT_DNS_DOH_PROVIDER"
}

assert_android_internet_status_contains() {
  local expected="$1" status="" deadline=$((SECONDS + ANDROID_UI_WAIT_SECS))
  local status_lower expected_lower
  expected_lower="$(printf '%s' "$expected" | tr '[:upper:]' '[:lower:]')"
  while ((SECONDS < deadline)); do
    android_ui_scroll_to resource internet-source-status || return 1
    status="$(android_ui_query resource internet-source-status descendant-text 2>/dev/null || true)"
    status_lower="$(printf '%s' "$status" | tr '[:upper:]' '[:lower:]')"
    if [[ "$status_lower" == *"$expected_lower"* ]]; then
      return 0
    fi
    sleep 0.25
  done
  echo "Android current Internet status was '$status', expected '$expected'" >&2
  return 1
}

configure_android_exit_dns_ui() {
  android_open_internet_settings_ui "Exit DNS configuration" || return 1
  android_ui_reset_scroll

  android_ui_scroll_to resource internet-source-picker || return 1
  tap_android_ui resource internet-source-picker || return 1
  wait_for_android_ui description "Internet source WireGuard VPN" || return 1
  tap_android_ui description "Internet source WireGuard VPN" || return 1
  sleep 0.5
  assert_android_internet_status_contains "WireGuard" || return 1

  local mode_description
  case "$EXIT_DNS_MODE" in
    automatic) mode_description="Automatic Exit DNS option" ;;
    encrypted) mode_description="Encrypted Exit DNS option" ;;
    through_exit) mode_description="Through exit Exit DNS option" ;;
    *)
      echo "Unknown Android Exit DNS UI mode: $EXIT_DNS_MODE" >&2
      return 1
      ;;
  esac
  android_ui_scroll_to description "$mode_description" || return 1
  tap_android_ui description "$mode_description" || return 1
  sleep 0.25

  if [[ "$EXIT_DNS_MODE" == "encrypted" ]]; then
    local provider_description
    case "$EXIT_DNS_DOH_PROVIDER" in
      cloudflare) provider_description="Cloudflare Exit DNS option" ;;
      quad9) provider_description="Quad9 Exit DNS option" ;;
      custom) provider_description="Custom Exit DNS option" ;;
      *)
        echo "Unknown Android Exit DNS UI provider: $EXIT_DNS_DOH_PROVIDER" >&2
        return 1
        ;;
    esac
    android_ui_scroll_to description "$provider_description" || return 1
    tap_android_ui description "$provider_description" || return 1
    sleep 0.25

    if [[ "$EXIT_DNS_DOH_PROVIDER" == "custom" ]]; then
      replace_android_ui_text exit-dns-custom-url ""
      replace_android_ui_text exit-dns-custom-bootstrap-ips ""
      assert_android_ui_validation "Enter an HTTPS DoH URL." || return 1

      replace_android_ui_text \
        exit-dns-custom-url \
        "http://resolver.invalid/dns-query"
      assert_android_ui_validation "DoH URL must use HTTPS." || return 1

      replace_android_ui_text exit-dns-custom-url "$EXIT_DNS_CUSTOM_DOH_URL"
      assert_android_ui_validation "Enter at least one bootstrap IP." || return 1
      replace_android_ui_text \
        exit-dns-custom-bootstrap-ips \
        "$EXIT_DNS_CUSTOM_DOH_BOOTSTRAP_IPS"
    fi
  elif [[ "$EXIT_DNS_MODE" == "through_exit" ]]; then
    replace_android_ui_text exit-dns-through-exit-servers ""
    assert_android_ui_validation "Enter at least one DNS server IP." || return 1
    replace_android_ui_text \
      exit-dns-through-exit-servers \
      "$EXIT_DNS_THROUGH_EXIT_SERVERS"
  fi

  assert_android_ui_save_enabled || return 1
  tap_android_ui resource exit-dns-save || return 1
  wait_for_android_exit_dns_persistence || return 1
  assert_android_exit_dns_ui_reloaded
}

android_direct_source_persisted() {
  if truthy "$RELEASE_BLACKBOX_GATE"; then
    [[ "$(android_ui_query resource internet-source-picker descendant-text 2>/dev/null || true)" == "This device" ]]
    return
  fi
  "$ADB" -s "$serial" exec-out run-as "$PACKAGE_NAME" \
    cat files/app-core/config.toml 2>/dev/null \
    | python3 -c '
import re
import sys

text = sys.stdin.read()
top_level = re.split(r"(?m)^\[", text, maxsplit=1)[0]
source_match = re.search(
    r"(?m)^\s*internet_source\s*=\s*\"([^\"]+)\"\s*$",
    top_level,
)
source = source_match.group(1) if source_match else "direct"
wireguard_match = re.search(
    r"(?ms)^\[wireguard_exit\]\s*$\n(.*?)(?=^\[|\Z)",
    text,
)
wireguard_enabled = bool(
    wireguard_match
    and re.search(
        r"(?m)^\s*enabled\s*=\s*true\s*$",
        wireguard_match.group(1),
    )
)
sys.exit(
    0
    if source in {"direct", "device"} and not wireguard_enabled
    else 1
)
'
}

select_android_direct_ui() {
  android_open_internet_settings_ui "Direct Internet transition" || return 1
  android_ui_reset_scroll
  android_ui_scroll_to resource internet-source-picker || return 1
  tap_android_ui resource internet-source-picker || return 1
  wait_for_android_ui description "Internet source This device" || return 1
  tap_android_ui description "Internet source This device" || return 1

  local deadline=$((SECONDS + ANDROID_UI_WAIT_SECS))
  while ((SECONDS < deadline)); do
    if android_direct_source_persisted; then
      assert_android_internet_status_contains "Direct" || return 1
      echo "Android shipped UI selected and persisted This device"
      return 0
    fi
    sleep 0.25
  done
  echo "Android shipped UI did not persist the Direct Internet source" >&2
  return 1
}

configure_android_exit_dns_debug() {
  local probe_id="$1"
  local internet_source="${2:-wireguard}"
  local wireguard_enabled="${3:-true}"
  local patch encoded result_path start now validation_error
  patch="$(
    python3 - \
      "$probe_id" \
      "$EXIT_DNS_MODE" \
      "$EXIT_DNS_DOH_PROVIDER" \
      "$EXIT_DNS_CUSTOM_DOH_URL" \
      "$EXIT_DNS_CUSTOM_DOH_BOOTSTRAP_IPS" \
      "$EXIT_DNS_THROUGH_EXIT_SERVERS" \
      "$internet_source" \
      "$wireguard_enabled" <<'PY'
import json
import sys

(
    probe_id,
    mode,
    provider,
    custom_url,
    bootstrap_ips,
    through_exit_servers,
    internet_source,
    wireguard_enabled,
) = sys.argv[1:]
print(json.dumps({
    "probeId": probe_id,
    "exitDnsMode": mode,
    "exitDnsDohProvider": provider,
    "exitDnsCustomDohUrl": custom_url,
    "exitDnsCustomDohBootstrapIps": bootstrap_ips,
    "exitDnsThroughExitServers": through_exit_servers,
    "internetSource": internet_source,
    "wireguardExitEnabled": wireguard_enabled == "true",
    "exitNode": "",
    "exitNodeLeakProtection": False,
}, separators=(",", ":")))
PY
  )"
  encoded="$(printf '%s' "$patch" | base64_no_wrap)"
  result_path="$(android_exit_dns_result_path)"
  mkdir -p "$RUNTIME_STATE_RESULT_DIR"
  rm -f "$result_path"
  "$ADB" -s "$serial" shell run-as "$PACKAGE_NAME" \
    rm -f "files/app-core/$EXIT_DNS_RESULT_FILE"
  start_main_activity \
    --es "$DEBUG_ACTION_EXTRA" set_exit_dns \
    --es "$DEBUG_EXIT_DNS_PATCH_BASE64_EXTRA" "$encoded"
  start="$(date +%s)"
  validation_error=""
  while true; do
    if "$ADB" -s "$serial" exec-out run-as "$PACKAGE_NAME" \
      cat "files/app-core/$EXIT_DNS_RESULT_FILE" >"$result_path.tmp" 2>/dev/null \
      && [[ -s "$result_path.tmp" ]]
    then
      if validation_error="$(
        python3 - \
          "$result_path.tmp" \
          "$probe_id" \
          "$EXIT_DNS_MODE" \
          "$EXIT_DNS_DOH_PROVIDER" \
          "$EXIT_DNS_CUSTOM_DOH_URL" \
          "$EXIT_DNS_CUSTOM_DOH_BOOTSTRAP_IPS" \
          "$EXIT_DNS_THROUGH_EXIT_SERVERS" \
          "$internet_source" \
          "$wireguard_enabled" <<'PY'
import json
import sys

path, probe_id, mode, provider, custom_url, bootstrap_ips, through_servers, source, wg = sys.argv[1:]
try:
    with open(path, encoding="utf-8") as fh:
        state = json.load(fh)
except (OSError, json.JSONDecodeError) as error:
    print(f"receipt is not complete JSON: {error}")
    raise SystemExit(1)
expected = {
    "probeId": probe_id,
    "exitDnsMode": mode,
    "exitDnsDohProvider": provider,
    "exitDnsCustomDohUrl": custom_url,
    "exitDnsCustomDohBootstrapIps": bootstrap_ips,
    "exitDnsThroughExitServers": through_servers,
    "internetSource": source,
    "wireguardExitEnabled": wg == "true",
}
errors = [
    f"{key}={state.get(key)!r} expected={value!r}"
    for key, value in expected.items()
    if state.get(key) != value
]
if state.get("error"):
    errors.append(f"error={state['error']!r}")
if errors:
    print("Android exit DNS settings receipt invalid: " + ", ".join(errors))
    sys.exit(1)
PY
      )"
      then
        mv "$result_path.tmp" "$result_path"
        echo "Android exit DNS production settings action passed: $result_path"
        return 0
      fi
    fi
    rm -f "$result_path.tmp"
    now="$(date +%s)"
    if (( now - start >= RUNTIME_STATE_WAIT_SECS )); then
      echo "Android exit DNS settings action did not produce a matching receipt: ${validation_error:-receipt missing}" >&2
      return 1
    fi
    sleep 1
  done
}

run_android_direct_while_tunnel_probe() {
  local result_path dns_servers underlying_dns
  result_path="$(android_network_probe_path direct-while-tunnel-connected)"
  mkdir -p "$RUNTIME_STATE_RESULT_DIR"
  if ! vpn_state_present || ! vpn_active; then
    echo "Android connected Direct probe failed: VPN service/network is not active" >&2
    return 1
  fi
  if android_vpn_has_default_route; then
    echo "Android connected Direct probe failed: active VPN still owns the default route" >&2
    return 1
  else
    local route_status="$?"
    if [[ "$route_status" -ne 1 ]]; then
      echo "Android connected Direct probe failed: active VPN routes were unavailable" >&2
      return 1
    fi
  fi
  if ! dns_servers="$(android_vpn_dns_servers)"; then
    echo "Android connected Direct probe failed: active VPN DNS state is unavailable" >&2
    return 1
  fi
  if [[ -n "$dns_servers" ]]; then
    echo "Android connected Direct probe failed: VPN still owns DNS: $dns_servers" >&2
    return 1
  fi
  if ! underlying_dns="$(android_validated_underlying_dns_servers)"; then
    echo "Android connected Direct probe failed: validated device DNS is unavailable" >&2
    return 1
  fi
  if [[ -n "$DIRECT_UNDERLYING_DNS_BASELINE" \
    && "$underlying_dns" != "$DIRECT_UNDERLYING_DNS_BASELINE" ]]
  then
    echo "Android connected Direct probe failed: device DNS changed during the transition" >&2
    return 1
  fi
  {
    printf 'vpnConnected=true\n'
    printf 'vpnDnsServers=\n'
    printf 'deviceDnsServers=%s\n' "$(tr '\n' ',' <<<"$underlying_dns" | sed 's/,$//')"
    printf 'publicHost=%s\n' "$DIRECT_PROBE_HOST"
    "$ADB" -s "$serial" shell ping -c 3 -W 3 "$DIRECT_PROBE_HOST"
  } >"$result_path" 2>&1 || {
    echo "Android connected Direct DNS/Internet probe failed: $result_path" >&2
    return 1
  }
  if ! vpn_active; then
    echo "Android connected Direct probe failed: VPN stopped during the probe" >&2
    return 1
  fi
  if ! run_android_app_network_probe \
    direct-while-tunnel-connected \
    "$DIRECT_PROBE_HOST" \
    "$DIRECT_PROBE_URL" \
    ""
  then
    return 1
  fi
  echo "Android native device DNS/Internet passed while the split VPN remained connected: $result_path"
}

copy_android_runtime_state() {
  local result_path
  result_path="$(android_runtime_state_path)"
  mkdir -p "$RUNTIME_STATE_RESULT_DIR"
  rm -f "$result_path.tmp"
  if "$ADB" -s "$serial" exec-out \
    run-as "$PACKAGE_NAME" cat files/app-core/mobile-runtime-state.json \
    >"$result_path.tmp" 2>/dev/null && [[ -s "$result_path.tmp" ]]
  then
    mv "$result_path.tmp" "$result_path"
    return 0
  fi
  rm -f "$result_path.tmp"
  return 1
}

copy_android_build_metadata() {
  local result_path
  result_path="$(android_build_metadata_path)"
  mkdir -p "$RUNTIME_STATE_RESULT_DIR"
  rm -f "$result_path.tmp"
  if "$ADB" -s "$serial" exec-out \
    run-as "$PACKAGE_NAME" sh -c 'test -s files/app-core/android-build-metadata.json && cat files/app-core/android-build-metadata.json' \
    >"$result_path.tmp" 2>/dev/null && [[ -s "$result_path.tmp" ]]
  then
    mv "$result_path.tmp" "$result_path"
    return 0
  fi
  rm -f "$result_path.tmp"
  return 1
}

validate_android_build_metadata() {
  local result_path
  result_path="$(android_build_metadata_path)"
  python3 - "$result_path" "$NVPN_BUILD_GIT_SHA" "$PACKAGE_NAME" <<'PY'
import json
import sys

path, expected_build_git_sha, expected_package = sys.argv[1], sys.argv[2], sys.argv[3]
try:
    with open(path, encoding="utf-8") as fh:
        metadata = json.load(fh)
except (OSError, json.JSONDecodeError) as error:
    print(f"Android build metadata invalid JSON: {error}", file=sys.stderr)
    sys.exit(1)

errors = []
actual_package = metadata.get("appPackageName")
if actual_package != expected_package:
    errors.append(f"appPackageName={actual_package!r} expected={expected_package!r}")
actual_build_git_sha = metadata.get("appBuildGitSha")
if expected_build_git_sha:
    if not actual_build_git_sha:
        errors.append(f"appBuildGitSha missing expected={expected_build_git_sha!r}")
    elif actual_build_git_sha != expected_build_git_sha:
        errors.append(
            f"appBuildGitSha={actual_build_git_sha!r} expected={expected_build_git_sha!r}"
        )

if errors:
    print("Android build metadata invalid: " + ", ".join(errors), file=sys.stderr)
    sys.exit(1)
PY
}

wait_for_android_build_metadata() {
  local start now last_error
  start="$(date +%s)"
  last_error=""
  while true; do
    if copy_android_build_metadata; then
      if last_error="$(validate_android_build_metadata 2>&1)"; then
        echo "Android build metadata passed: $(android_build_metadata_path)"
        return 0
      fi
    else
      last_error="failed to copy files/app-core/android-build-metadata.json from debug app sandbox"
    fi
    now="$(date +%s)"
    if (( now - start >= RUNTIME_STATE_WAIT_SECS )); then
      echo "$last_error" >&2
      return 1
    fi
    sleep 1
  done
}

validate_android_runtime_state() {
  local result_path
  result_path="$(android_runtime_state_path)"
  python3 - "$result_path" "$RUNTIME_STATE_MAX_AGE_SECS" <<'PY'
import json
import sys
import time

path = sys.argv[1]
max_age = int(sys.argv[2])
with open(path, encoding="utf-8") as fh:
    state = json.load(fh)

errors = []
if state.get("vpnEnabled") is not True:
    errors.append(f"vpnEnabled={state.get('vpnEnabled')!r}")
if state.get("vpnActive") is not True:
    errors.append(f"vpnActive={state.get('vpnActive')!r}")

updated_at = state.get("updatedAt")
now = int(time.time())
if not isinstance(updated_at, int) or updated_at <= 0:
    errors.append(f"updatedAt={updated_at!r}")
elif updated_at - now > 120:
    errors.append(f"updatedAt future skew={updated_at - now}s")
elif now - updated_at > max_age:
    errors.append(f"updatedAt age={now - updated_at}s")

for key in (
    "tunPacketsRead",
    "tunBytesRead",
    "tunPacketsWritten",
    "tunBytesWritten",
    "tunPacketsDropped",
):
    value = state.get(key)
    if not isinstance(value, int) or value < 0:
        errors.append(f"{key}={value!r}")

if errors:
    print("Android runtime state invalid: " + ", ".join(errors), file=sys.stderr)
    sys.exit(1)
PY
}

android_runtime_state_number() {
  local key="$1"
  local result_path
  result_path="$(android_runtime_state_path)"
  python3 - "$result_path" "$key" <<'PY'
import json
import sys

path, key = sys.argv[1], sys.argv[2]
with open(path, encoding="utf-8") as fh:
    value = json.load(fh).get(key)
if not isinstance(value, int):
    sys.exit(1)
print(value)
PY
}

android_runtime_state_counters() {
  local result_path
  result_path="$(android_runtime_state_path)"
  python3 - "$result_path" <<'PY'
import json
import sys

path = sys.argv[1]
keys = (
    "tunPacketsRead",
    "tunBytesRead",
    "tunPacketsWritten",
    "tunBytesWritten",
    "tunPacketsDropped",
)
with open(path, encoding="utf-8") as fh:
    state = json.load(fh)
values = [state.get(key) for key in keys]
if not all(isinstance(value, int) and value >= 0 for value in values):
    sys.exit(1)
print("\t".join(str(value) for value in values))
PY
}

android_vpn_interface_name() {
  local connectivity
  connectivity="$("$ADB" -s "$serial" shell dumpsys connectivity 2>/dev/null | tr -d '\r')" || return 1
  python3 -c '
import re
import sys

text = sys.stdin.read()
for block in re.split(r"(?=NetworkAgentInfo\{)", text):
    if "ni{VPN CONNECTED" not in block:
        continue
    match = re.search(r"InterfaceName:\s*([^,\s}\]]+)", block)
    if match:
        print(match.group(1))
        sys.exit(0)
sys.exit(1)
' <<<"$connectivity"
}

capture_android_vpn_link_stats() {
  local label="$1"
  local body captured iface result_path status unavailable_reason source
  local timestamp
  result_path="$(android_vpn_link_stats_path)"
  body="$(mktemp)"
  captured=0
  status=0
  unavailable_reason=""
  source="ip -s link"
  timestamp="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  if ! iface="$(android_vpn_interface_name)"; then
    iface="unknown"
    unavailable_reason="unable to resolve active Android VPN interface"
  elif "$ADB" -s "$serial" shell ip -s link show dev "$iface" 2>&1 | tr -d '\r' >"$body"; then
    if grep -Eq '(^|[[:space:]])RX:' "$body" && grep -Eq '(^|[[:space:]])TX:' "$body"; then
      captured=1
    else
      unavailable_reason="ip -s link show dev $iface returned no RX/TX counters"
    fi
  else
    status=$?
    unavailable_reason="ip -s link show dev $iface exited $status"
  fi
  if [[ "$captured" -ne 1 && "$iface" != "unknown" ]]; then
    local proc_body
    proc_body="$(mktemp)"
    if "$ADB" -s "$serial" shell cat /proc/net/dev 2>&1 \
      | tr -d '\r' \
      | awk -v iface="$iface" '
          {
            split($1, name, ":")
            if (name[1] == iface) {
              print
              found = 1
            }
          }
          END { exit found ? 0 : 1 }
        ' >"$proc_body"
    then
      mv "$proc_body" "$body"
      captured=1
      source="/proc/net/dev"
    else
      rm -f "$proc_body"
    fi
  fi
  mkdir -p "$RUNTIME_STATE_RESULT_DIR"
  {
    printf '## label=%s timestamp=%s iface=%s linkStats=%s source=%s\n' \
      "$label" "$timestamp" "$iface" \
      "$([[ "$captured" -eq 1 ]] && printf captured || printf unavailable)" "$source"
    if [[ "$captured" -eq 1 ]]; then
      cat "$body"
    else
      printf 'unavailable: %s\n' "$unavailable_reason"
      if [[ -s "$body" ]]; then
        sed 's/^/    /' "$body"
      fi
    fi
    printf '\n'
  } >>"$result_path"
  write_android_vpn_link_stats_summary "$label" "$timestamp" "$iface" "$source" "$result_path" "$body" "$captured"
  rm -f "$body"
  if [[ "$captured" -eq 1 ]]; then
    echo "Android VPN link counters captured ($label): $result_path iface=$iface"
    return 0
  else
    echo "Android VPN link counters unavailable ($label): $result_path iface=$iface reason=$unavailable_reason"
    return 1
  fi
}

write_android_vpn_link_stats_summary() {
  local label="$1"
  local timestamp="$2"
  local iface="$3"
  local source="$4"
  local raw_path="$5"
  local body_path="$6"
  local captured="$7"
  local summary_path
  summary_path="$(android_vpn_link_stats_summary_path)"
  if [[ ! -s "$summary_path" ]]; then
    printf 'label\ttimestamp\tiface\tsource\tparseStatus\trxBytes\trxPackets\trxDropped\ttxBytes\ttxPackets\ttxDropped\trawOutput\n' >"$summary_path"
  fi
  if [[ "$captured" -ne 1 ]]; then
    printf '%s\t%s\t%s\t%s\tunavailable\t\t\t\t\t\t\t%s\n' \
      "$label" "$timestamp" "$iface" "$source" "$raw_path" >>"$summary_path"
    echo "Android VPN link counter summary: $summary_path label=$label iface=$iface"
    return 0
  fi
  if ! awk -v label="$label" -v timestamp="$timestamp" -v iface="$iface" \
    -v source="$source" -v raw="$raw_path" '
      function emit(rx_bytes, rx_packets, rx_dropped, tx_bytes, tx_packets, tx_dropped) {
        printf "%s\t%s\t%s\t%s\tparsed\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
          label, timestamp, iface, source,
          rx_bytes, rx_packets, rx_dropped, tx_bytes, tx_packets, tx_dropped, raw
        found = 1
      }
      $1 == iface ":" && NF >= 17 { emit($2, $3, $5, $10, $11, $13); next }
      $1 == "RX:" { want_rx = 1; next }
      want_rx && NF >= 4 && $1 ~ /^[0-9]+$/ {
        rx_bytes = $1; rx_packets = $2; rx_dropped = $4; want_rx = 0; next
      }
      $1 == "TX:" { want_tx = 1; next }
      want_tx && NF >= 4 && $1 ~ /^[0-9]+$/ {
        emit(rx_bytes, rx_packets, rx_dropped, $1, $2, $4); want_tx = 0; next
      }
      END { exit found ? 0 : 1 }
    ' "$body_path" >>"$summary_path"
  then
    printf '%s\t%s\t%s\t%s\tunparsed\t\t\t\t\t\t\t%s\n' \
      "$label" "$timestamp" "$iface" "$source" "$raw_path" >>"$summary_path"
  fi
  echo "Android VPN link counter summary: $summary_path label=$label iface=$iface"
}

summarize_android_ping_probe() {
  local result_path="$1"
  local exit_status="$2"
  local summary_path
  summary_path="$(android_ping_probe_summary_path)"
  python3 - "$result_path" "$summary_path" "$exit_status" "$TUN_PACKET_PROBE_TARGET" <<'PY'
import json
import math
import re
import sys

path, summary_path, exit_status, target = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
text = open(path, encoding="utf-8", errors="replace").read()
loss = None
loss_match = re.search(r"(\d+(?:\.\d+)?)%\s+packet loss", text)
if loss_match:
    loss = float(loss_match.group(1))

transmitted = None
received = None
packet_match = re.search(r"(\d+)\s+packets transmitted,\s+(\d+)\s+(?:packets )?received", text)
if packet_match:
    transmitted = int(packet_match.group(1))
    received = int(packet_match.group(2))

min_ms = None
avg_ms = None
max_ms = None
jitter_ms = None
rtt_match = re.search(
    r"(?:rtt|round-trip)[^=]*=\s*([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)\s*ms",
    text,
)
if rtt_match:
    min_ms = float(rtt_match.group(1))
    avg_ms = float(rtt_match.group(2))
    max_ms = float(rtt_match.group(3))
    jitter_ms = float(rtt_match.group(4))

samples = sorted(float(match) for match in re.findall(r"time[=<]\s*([\d.]+)", text))

def percentile(values, pct):
    if not values:
        return None
    index = math.ceil(len(values) * pct / 100) - 1
    index = min(max(index, 0), len(values) - 1)
    return round(values[index], 3)

summary = {
    "target": target,
    "exitStatus": int(exit_status),
    "transmitted": transmitted,
    "received": received,
    "packetLossPct": loss,
    "samples": len(samples),
    "minMs": min_ms,
    "avgMs": avg_ms,
    "maxMs": max_ms,
    "mdevMs": jitter_ms,
    "p95Ms": percentile(samples, 95),
    "p99Ms": percentile(samples, 99),
    "rawOutput": path,
}
with open(summary_path, "w", encoding="utf-8") as fh:
    json.dump(summary, fh, sort_keys=True, indent=2)
    fh.write("\n")

def display(value, suffix=""):
    if value is None:
        return "unknown"
    if isinstance(value, float):
        return f"{value:.3f}".rstrip("0").rstrip(".") + suffix
    return f"{value}{suffix}"

print(
    "Android packet probe ping summary: "
    f"target={target} exit={exit_status} loss={display(loss, '%')} "
    f"samples={len(samples)} avg_ms={display(avg_ms)} p95_ms={display(summary['p95Ms'])} "
    f"p99_ms={display(summary['p99Ms'])} max_ms={display(max_ms)} "
    f"mdev_ms={display(jitter_ms)} output={path} summary={summary_path}"
)
PY
}

write_android_tun_packet_probe_summary() {
  local baseline="$1"
  local current="$2"
  local required_increase="$3"
  local baseline_bytes="$4"
  local current_bytes="$5"
  local baseline_written="$6"
  local current_written="$7"
  local baseline_bytes_written="$8"
  local current_bytes_written="$9"
  local baseline_dropped="${10}"
  local current_dropped="${11}"
  local ping_path="${12}"
  local ping_status="${13}"
  local first_observed_ms="${14}"
  local elapsed_ms="${15}"
  local polls="${16}"
  local poll_interval_ms="${17}"
  local summary_path
  summary_path="$(android_tun_packet_probe_summary_path)"
  python3 "$ROOT/scripts/write-mobile-android-tun-summary.py" \
    "$summary_path" \
    "$TUN_PACKET_PROBE_TARGET" \
    "$TUN_PACKET_PROBE_TIMEOUT_SECS" \
    "$baseline" \
    "$current" \
    "$required_increase" \
    "$baseline_bytes" \
    "$current_bytes" \
    "$baseline_written" \
    "$current_written" \
    "$baseline_bytes_written" \
    "$current_bytes_written" \
    "$baseline_dropped" \
    "$current_dropped" \
    "$ping_path" \
    "$ping_status" \
    "$first_observed_ms" \
    "$elapsed_ms" \
    "$polls" \
    "$poll_interval_ms" \
    "$TUN_PACKET_PROBE_REQUIRE_REPLY" \
    "$(android_runtime_state_path)" \
    "$(android_ping_probe_summary_path)" \
    "$(android_vpn_link_stats_path)" \
    "$(android_vpn_link_stats_summary_path)" \
    "$(android_build_metadata_path)"
  printf '%s\n' "$summary_path"
}

wait_for_android_runtime_state() {
  local start now last_error
  start="$(date +%s)"
  last_error=""
  while true; do
    if copy_android_runtime_state; then
      if last_error="$(validate_android_runtime_state 2>&1)"; then
        echo "Android runtime state passed: $(android_runtime_state_path)"
        return 0
      fi
    else
      last_error="failed to copy files/app-core/mobile-runtime-state.json from debug app sandbox"
    fi
    now="$(date +%s)"
    if (( now - start >= RUNTIME_STATE_WAIT_SECS )); then
      echo "$last_error" >&2
      return 1
    fi
    sleep 1
  done
}

wait_for_tun_packets_read_after() {
  local baseline="$1"
  local required_increase="$2"
  local baseline_dropped="$3"
  local baseline_bytes="$4"
  local start_ms="$5"
  local start now current current_bytes current_written current_bytes_written current_dropped bytes_delta last_error
  local now_ms first_observed_ms elapsed_ms polls poll_interval_ms poll_interval_secs observed
  start="$(date +%s)"
  first_observed_ms=""
  polls=0
  poll_interval_ms=100
  poll_interval_secs=0.1
  last_error=""
  while true; do
    polls=$((polls + 1))
    if copy_android_runtime_state; then
      if last_error="$(validate_android_runtime_state 2>&1)"; then
        current="$(android_runtime_state_number tunPacketsRead 2>/dev/null || true)"
        current_bytes="$(android_runtime_state_number tunBytesRead 2>/dev/null || true)"
        current_written="$(android_runtime_state_number tunPacketsWritten 2>/dev/null || true)"
        current_bytes_written="$(android_runtime_state_number tunBytesWritten 2>/dev/null || true)"
        current_dropped="$(android_runtime_state_number tunPacketsDropped 2>/dev/null || true)"
        now_ms="$(epoch_ms)"
        if [[ "$current" =~ ^[0-9]+$ ]]; then
          observed="$((current - baseline))"
          if (( observed > 0 )) && [[ -z "$first_observed_ms" ]]; then
            first_observed_ms="$((now_ms - start_ms))"
          fi
        fi
        if [[ "$current_dropped" =~ ^[0-9]+$ ]] && (( current_dropped > baseline_dropped )); then
          echo "tunPacketsDropped increased during probe (baseline=$baseline_dropped current=$current_dropped)" >&2
          return 1
        fi
        if [[ "$current" =~ ^[0-9]+$ ]] && (( current >= baseline + required_increase )); then
          elapsed_ms="$((now_ms - start_ms))"
          bytes_delta="unknown"
          if [[ "$current_bytes" =~ ^[0-9]+$ ]]; then
            bytes_delta="$((current_bytes - baseline_bytes))"
          fi
          TUN_PACKET_PROBE_FINAL_READ="$current"
          TUN_PACKET_PROBE_FINAL_BYTES_READ="$current_bytes"
          TUN_PACKET_PROBE_FINAL_WRITTEN="$current_written"
          TUN_PACKET_PROBE_FINAL_BYTES_WRITTEN="$current_bytes_written"
          TUN_PACKET_PROBE_FINAL_DROPPED="$current_dropped"
          TUN_PACKET_PROBE_FIRST_OBSERVED_MS="${first_observed_ms:-$elapsed_ms}"
          TUN_PACKET_PROBE_ELAPSED_MS="$elapsed_ms"
          TUN_PACKET_PROBE_POLLS="$polls"
          TUN_PACKET_PROBE_POLL_INTERVAL_MS="$poll_interval_ms"
          TUN_PACKET_PROBE_BYTES_DELTA="$bytes_delta"
          echo "Android TUN packet probe observed: tunPacketsRead $baseline->$current observed=$((current - baseline))/$required_increase tunBytesReadDelta=$bytes_delta tunPacketsDropped=$baseline_dropped->$current_dropped firstObservedMs=${first_observed_ms:-$elapsed_ms} elapsedMs=$elapsed_ms polls=$polls target=$TUN_PACKET_PROBE_TARGET"
          return 0
        fi
        last_error="tunPacketsRead did not increase enough after probe (baseline=$baseline current=${current:-missing} required=$required_increase tunPacketsDropped=${current_dropped:-missing})"
      fi
    else
      last_error="failed to copy files/app-core/mobile-runtime-state.json from debug app sandbox"
    fi
    now="$(date +%s)"
    if (( now - start >= TUN_PACKET_PROBE_WAIT_SECS )); then
      echo "$last_error" >&2
      return 1
    fi
    sleep "$poll_interval_secs"
  done
}

run_android_tun_packet_probe() {
  truthy "$TUN_PACKET_PROBE" || return 0
  local baseline baseline_bytes baseline_dropped count remote_cmd ping_path ping_status probe_start_ms
  local ping_pid summary_path wait_status
  local baseline_written baseline_bytes_written
  IFS=$'\t' read -r baseline baseline_bytes baseline_written baseline_bytes_written baseline_dropped \
    <<<"$(android_runtime_state_counters 2>/dev/null || printf '0\t0\t0\t0\t0')"
  [[ "$baseline" =~ ^[0-9]+$ ]] || baseline=0
  [[ "$baseline_bytes" =~ ^[0-9]+$ ]] || baseline_bytes=0
  [[ "$baseline_written" =~ ^[0-9]+$ ]] || baseline_written=0
  [[ "$baseline_bytes_written" =~ ^[0-9]+$ ]] || baseline_bytes_written=0
  [[ "$baseline_dropped" =~ ^[0-9]+$ ]] || baseline_dropped=0
  count="$TUN_PACKET_PROBE_COUNT"
  [[ "$count" =~ ^[0-9]+$ ]] || count=4
  (( count > 0 )) || count=1
  ping_path="$(android_ping_probe_path)"
  mkdir -p "$RUNTIME_STATE_RESULT_DIR"
  remote_cmd="ping -c $count -W $TUN_PACKET_PROBE_TIMEOUT_SECS $TUN_PACKET_PROBE_TARGET"
  probe_start_ms="$(epoch_ms)"
  "$ADB" -s "$serial" shell "$remote_cmd" >"$ping_path" 2>&1 &
  ping_pid="$!"
  wait_status=0
  wait_for_tun_packets_read_after "$baseline" "$count" "$baseline_dropped" "$baseline_bytes" "$probe_start_ms" || wait_status=$?
  if wait "$ping_pid"; then
    ping_status=0
  else
    ping_status=$?
  fi
  summarize_android_ping_probe "$ping_path" "$ping_status"
  if (( wait_status != 0 )); then
    return "$wait_status"
  fi
  summary_path="$(
    write_android_tun_packet_probe_summary \
      "$baseline" \
      "$TUN_PACKET_PROBE_FINAL_READ" \
      "$count" \
      "$baseline_bytes" \
      "$TUN_PACKET_PROBE_FINAL_BYTES_READ" \
      "$baseline_written" \
      "$TUN_PACKET_PROBE_FINAL_WRITTEN" \
      "$baseline_bytes_written" \
      "$TUN_PACKET_PROBE_FINAL_BYTES_WRITTEN" \
      "$baseline_dropped" \
      "$TUN_PACKET_PROBE_FINAL_DROPPED" \
      "$ping_path" \
      "$ping_status" \
      "$TUN_PACKET_PROBE_FIRST_OBSERVED_MS" \
      "$TUN_PACKET_PROBE_ELAPSED_MS" \
      "$TUN_PACKET_PROBE_POLLS" \
      "$TUN_PACKET_PROBE_POLL_INTERVAL_MS"
  )"
  if truthy "$TUN_PACKET_PROBE_REQUIRE_REPLY"; then
    if ! python3 - "$summary_path" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as fh:
    summary = json.load(fh)

errors = []
if not isinstance(summary.get("pingReceived"), int) or summary["pingReceived"] <= 0:
    errors.append(f"pingReceived={summary.get('pingReceived')!r}")
if summary.get("writtenIncreased") is not True:
    errors.append(
        "tunPacketsWritten="
        f"{summary.get('baselineWritten')!r}->{summary.get('finalWritten')!r}"
    )
if summary.get("bytesWrittenIncreased") is not True:
    errors.append(
        "tunBytesWritten="
        f"{summary.get('baselineBytesWritten')!r}->{summary.get('finalBytesWritten')!r}"
    )
if summary.get("droppedIncreased") is True:
    errors.append(f"droppedDelta={summary.get('droppedDelta')!r}")
if errors:
    print("Android TUN reply probe failed: " + ", ".join(errors), file=sys.stderr)
    sys.exit(1)
PY
    then
      return 1
    fi
  fi
  echo "Android TUN packet probe passed: tunPacketsRead $baseline->$TUN_PACKET_PROBE_FINAL_READ observed=$((TUN_PACKET_PROBE_FINAL_READ - baseline))/$count tunBytesReadDelta=$TUN_PACKET_PROBE_BYTES_DELTA tunPacketsWritten=$baseline_written->$TUN_PACKET_PROBE_FINAL_WRITTEN tunBytesWritten=$baseline_bytes_written->$TUN_PACKET_PROBE_FINAL_BYTES_WRITTEN tunPacketsDropped=$baseline_dropped->$TUN_PACKET_PROBE_FINAL_DROPPED firstObservedMs=$TUN_PACKET_PROBE_FIRST_OBSERVED_MS elapsedMs=$TUN_PACKET_PROBE_ELAPSED_MS polls=$TUN_PACKET_PROBE_POLLS target=$TUN_PACKET_PROBE_TARGET summary=$summary_path"
  capture_android_vpn_link_stats "after-probe" || true
}

cleanup_android_vpn_after_pass() {
  truthy "$cleanup_after_vpn_cycle" || return 0
  if truthy "$RELEASE_BLACKBOX_GATE"; then
    local expected_count=""
    if [[ "$ANDROID_RELEASE_NATIVE_TUNNEL_START_COUNT" =~ ^[0-9]+$ ]]; then
      expected_count="$ANDROID_RELEASE_NATIVE_TUNNEL_START_COUNT"
    fi
    if android_release_disconnect_ui \
      && android_release_wait_stable_quiescence \
        post-pass-cleanup "$expected_count"
    then
      vpn_cleanup_armed=0
      return 0
    fi
    return 1
  fi
  start_main_activity --es "$DEBUG_ACTION_EXTRA" disconnect
  if wait_until "$VPN_STOP_WAIT_SECS" vpn_inactive; then
    vpn_cleanup_armed=0
    echo "Android VPN cleanup passed: debug disconnect left no active VPN service/network"
    return 0
  fi
  dump_vpn_diagnostics
  echo "Android smoke failed: VPN remained active after post-pass cleanup." >&2
  return 1
}

cleanup_android_vpn_on_exit() {
  local status="$?" cleanup_needed=0 cleanup_verified=0 release_toggle=""
  trap - EXIT
  if ! android_underlay_restore_home; then
    if [[ "$status" -eq 0 ]]; then
      status=1
    fi
  fi
  mobile_continuity_stop
  if [[ -n "$ANDROID_CAPTURED_PROBE_REMOTE_JAR" \
    && -n "${ADB:-}" \
    && -n "$serial" ]]
  then
    "$ADB" -s "$serial" shell rm -f "$ANDROID_CAPTURED_PROBE_REMOTE_JAR" \
      >/dev/null 2>&1 || true
  fi
  if [[ -n "$ANDROID_CAPTURED_PROBE_BUILD_DIR" \
    && -d "$ANDROID_CAPTURED_PROBE_BUILD_DIR" ]]
  then
    find "$ANDROID_CAPTURED_PROBE_BUILD_DIR" -type f -delete
    rmdir "$ANDROID_CAPTURED_PROBE_BUILD_DIR" 2>/dev/null || true
  fi
  if [[ -n "${ADB:-}" && -n "$serial" ]]; then
    if [[ "$vpn_cleanup_armed" -eq 1 ]]; then
      cleanup_needed=1
    elif truthy "$RELEASE_BLACKBOX_GATE"; then
      if vpn_state_present; then
        cleanup_needed=1
      else
        release_toggle="$(
          android_release_vpn_toggle_checked 2>/dev/null || true
        )"
        [[ "$release_toggle" == "true" ]] && cleanup_needed=1
      fi
    fi
  fi
  if [[ "$cleanup_needed" -eq 1 ]]; then
    # A successful gate must have completed and disarmed its normal cleanup.
    # Needing the EXIT path is itself a release-gate failure even when the
    # device can be restored safely here.
    if [[ "$status" -eq 0 ]]; then
      status=1
    fi
    if truthy "$RELEASE_BLACKBOX_GATE"; then
      if android_release_emergency_cleanup; then
        cleanup_verified=1
      fi
    else
      start_main_activity --es "$DEBUG_ACTION_EXTRA" disconnect >/dev/null 2>&1 || true
      if ! wait_until "$VPN_STOP_WAIT_SECS" vpn_inactive; then
        "$ADB" -s "$serial" shell am force-stop "$PACKAGE_NAME" \
          >/dev/null 2>&1 || true
      fi
      if wait_until "$VPN_STOP_WAIT_SECS" vpn_inactive; then
        cleanup_verified=1
      fi
    fi
    if [[ "$cleanup_verified" -eq 1 ]]; then
      if truthy "$RELEASE_BLACKBOX_GATE"; then
        echo "Android VPN emergency cleanup verified: OS VPN inactive, shipped toggle Off, native start count stable"
      else
        echo "Android VPN emergency cleanup verified: no active test service/network"
      fi
    else
      echo "Android VPN emergency cleanup failed; disable the VPN in Android Settings before replacing the app." >&2
      if [[ "$status" -eq 0 ]]; then
        status=1
      fi
    fi
  fi
  if [[
    "$PACKAGE_NAME" != "$CANONICAL_PACKAGE_NAME" &&
    "${NVPN_ANDROID_KEEP_TEST_PACKAGE:-0}" != "1" &&
    -n "${ADB:-}" &&
    -n "$serial"
  ]]; then
    "$ADB" -s "$serial" uninstall "$PACKAGE_NAME" >/dev/null 2>&1 || true
  fi
  exit "$status"
}

trap cleanup_android_vpn_on_exit EXIT

android_sdk() {
  "$ADB" -s "$serial" shell getprop ro.build.version.sdk | tr -d '\r'
}

grant_permission_if_declared() {
  local permission="$1"
  "$ADB" -s "$serial" shell pm grant "$PACKAGE_NAME" "$permission" >/dev/null 2>&1 || true
}

grant_debug_runtime_permissions() {
  local sdk
  sdk="$(android_sdk)"
  if [[ "$sdk" =~ ^[0-9]+$ && "$sdk" -ge 36 ]]; then
    grant_permission_if_declared android.permission.NEARBY_WIFI_DEVICES
  fi
  if [[ "$sdk" =~ ^[0-9]+$ && "$sdk" -ge 37 ]]; then
    grant_permission_if_declared android.permission.ACCESS_LOCAL_NETWORK
  fi
}

tap_ui_resource() {
  local resource="$1"
  local package="${2:-}"
  local remote="/sdcard/nvpn-window.xml"
  local xml
  local point
  xml="$(mktemp)"
  if ! "$ADB" -s "$serial" shell uiautomator dump "$remote" >/dev/null 2>&1; then
    rm -f "$xml"
    return 1
  fi
  if ! "$ADB" -s "$serial" pull "$remote" "$xml" >/dev/null 2>&1; then
    rm -f "$xml"
    return 1
  fi
  point="$(python3 - "$xml" "$resource" "$package" <<'PY'
import re
import sys

xml_path, resource, package = sys.argv[1], sys.argv[2], sys.argv[3]
xml = open(xml_path, encoding="utf-8").read()
for node in re.findall(r"<node [^>]+>", xml):
    rid = re.search(r'resource-id="([^"]*)"', node)
    pkg = re.search(r'package="([^"]*)"', node)
    bounds = re.search(r'bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"', node)
    enabled = re.search(r'enabled="([^"]*)"', node)
    if package and (not pkg or pkg.group(1) != package):
        continue
    if rid and rid.group(1) == resource and bounds and (not enabled or enabled.group(1) == "true"):
        left, top, right, bottom = map(int, bounds.groups())
        print((left + right) // 2, (top + bottom) // 2)
        sys.exit(0)
sys.exit(1)
PY
  )" || {
    rm -f "$xml"
    return 1
  }
  rm -f "$xml"
  "$ADB" -s "$serial" shell input tap $point
}

android_top_activity() {
  "$ADB" -s "$serial" shell dumpsys activity activities 2>/dev/null \
    | tr -d '\r' \
    | sed -nE \
      's/.*(topResumedActivity|mResumedActivity).* u[0-9]+ ([^ ]+\/[^ ]+) .*/\2/p' \
    | head -n 1
}

maybe_accept_vpn_dialog() {
  [[ "$accept_vpn_dialog" == "1" || "$accept_vpn_dialog" == "true" ]] || return 0
  local start now activity pending_prompt vpn_tapped
  start="$(date +%s)"
  pending_prompt=""
  vpn_tapped=0
  while true; do
    if vpn_active; then
      return 0
    fi
    activity="$(android_top_activity)"
    case "$activity" in
      com.android.permissioncontroller/.permission.ui.GrantPermissionsActivity|\
      com.android.permissioncontroller/com.android.permissioncontroller.permission.ui.GrantPermissionsActivity)
        pending_prompt="local-network permission"
        if tap_ui_resource \
          "com.android.permissioncontroller:id/permission_allow_button" \
          "com.android.permissioncontroller"
        then
          pending_prompt=""
        fi
        ;;
      com.android.permissioncontroller/*)
        echo "Unknown Android system prompt: $activity" >&2
        return 1
        ;;
      com.android.vpndialogs/*)
        pending_prompt="VPN confirmation"
        if tap_ui_resource "android:id/button1" "com.android.vpndialogs"; then
          vpn_tapped=1
          pending_prompt=""
        fi
        ;;
      "$PACKAGE_NAME"/*|"")
        if [[ -n "$pending_prompt" ]]; then
          echo "Android $pending_prompt was denied or had no known affirmative control" >&2
          return 1
        fi
        [[ "$vpn_tapped" -eq 0 ]] || return 0
        ;;
      *)
        echo "Unknown Android system prompt: $activity" >&2
        return 1
        ;;
    esac
    now="$(date +%s)"
    if (( now - start >= 8 )); then
      if [[ -n "$pending_prompt" ]]; then
        echo "Android $pending_prompt prompt had no known affirmative control" >&2
        return 1
      fi
      return 0
    fi
    sleep 0.5
  done
}

base64_no_wrap() {
  base64 | tr -d '\n'
}

wireguard_config() {
  if truthy "$RELEASE_BLACKBOX_GATE"; then
    if [[ -n "$RELEASE_WIREGUARD_CONFIG_FILE" ]]; then
      cat "$RELEASE_WIREGUARD_CONFIG_FILE"
      return
    fi
    printf '%s' "$RELEASE_WIREGUARD_CONFIG"
    return
  fi
  if [[ -n "$DEBUG_WIREGUARD_CONFIG_FILE" ]]; then
    cat "$DEBUG_WIREGUARD_CONFIG_FILE"
    return
  fi
  printf '%s' "$DEBUG_WIREGUARD_CONFIG"
}

start_main_activity() {
  "$ADB" -s "$serial" shell am start -n "$MAIN_ACTIVITY" "$@" >/dev/null
}

android_app_pid() {
  "$ADB" -s "$serial" shell pidof "$PACKAGE_NAME" 2>/dev/null \
    | tr -d '\r' \
    | awk '{ print $1 }'
}

android_app_process_running() {
  [[ -n "$(android_app_pid)" ]]
}

assert_single_android_app_process() {
  local pids count
  pids="$("$ADB" -s "$serial" shell pidof "$PACKAGE_NAME" 2>/dev/null \
    | tr -d '\r' || true)"
  count="$(awk '{ print NF }' <<<"$pids")"
  if [[ "$count" != "1" ]]; then
    echo "Android smoke requires exactly one canonical app process; found $count." >&2
    return 1
  fi
}

android_activity_resumed() {
  "$ADB" -s "$serial" shell dumpsys activity activities 2>/dev/null \
    | tr -d '\r' \
    | grep -F "topResumedActivity=" \
    | grep -Fq "$MAIN_ACTIVITY"
}

run_android_activity_lifecycle_gate() {
  truthy "$ANDROID_LIFECYCLE_GATE" || return 0
  local before_pid background_pid foreground_pid
  before_pid="$(android_app_pid)"
  if [[ -z "$before_pid" ]]; then
    echo "Android lifecycle gate failed: app process is not running" >&2
    return 1
  fi

  "$ADB" -s "$serial" shell input keyevent KEYCODE_HOME
  sleep "$ANDROID_LIFECYCLE_BACKGROUND_DWELL_SECS"
  background_pid="$(android_app_pid)"
  if [[ "$background_pid" != "$before_pid" ]]; then
    echo "Android lifecycle gate failed: app process did not survive backgrounding" >&2
    return 1
  fi

  start_main_activity
  if ! wait_until 5 android_activity_resumed; then
    echo "Android lifecycle gate failed: Activity did not resume" >&2
    return 1
  fi
  foreground_pid="$(android_app_pid)"
  if [[ "$foreground_pid" != "$before_pid" ]]; then
    echo "Android lifecycle gate failed: app process restarted while foregrounding" >&2
    return 1
  fi
  echo "Android background/foreground lifecycle gate passed"
}

run_android_active_vpn_lifecycle_gate() {
  if ! truthy "$ANDROID_LIFECYCLE_GATE"; then
    "$ADB" -s "$serial" shell input keyevent KEYCODE_HOME \
      && run_android_idle_cpu_gate "Android background active VPN"
    return $?
  fi

  if ! [[ "$ANDROID_LIFECYCLE_CYCLES" =~ ^[1-9][0-9]*$ ]] \
    || ! [[ "$ANDROID_LIFECYCLE_BACKGROUND_DWELL_SECS" =~ ^[0-9]+$ ]] \
    || (( ANDROID_LIFECYCLE_BACKGROUND_DWELL_SECS < 10 ))
  then
    echo "Android active lifecycle requires positive cycles and at least 10s background dwell" >&2
    return 1
  fi

  local before_pid background_pid foreground_pid cycle background_started elapsed remaining
  before_pid="$(android_app_pid)"
  if [[ -z "$before_pid" ]] || ! vpn_active; then
    echo "Android active lifecycle gate failed: app process or VPN is not active" >&2
    return 1
  fi

  for cycle in $(seq 1 "$ANDROID_LIFECYCLE_CYCLES"); do
    background_started="$(date +%s)"
    if ! "$ADB" -s "$serial" shell input keyevent KEYCODE_HOME \
      || ! run_android_idle_cpu_gate "Android background active VPN cycle $cycle"
    then
      echo "Android active lifecycle gate failed in cycle $cycle: could not background/sample the app" >&2
      return 1
    fi
    elapsed="$(( $(date +%s) - background_started ))"
    remaining="$((ANDROID_LIFECYCLE_BACKGROUND_DWELL_SECS - elapsed))"
    if (( remaining > 0 )); then
      sleep "$remaining"
    fi
    background_pid="$(android_app_pid)"
    if [[ "$background_pid" != "$before_pid" ]] || ! vpn_active; then
      echo "Android active lifecycle gate failed in cycle $cycle: app process or VPN did not survive backgrounding" >&2
      return 1
    fi

    if ! start_main_activity; then
      echo "Android active lifecycle gate failed in cycle $cycle: Activity launch failed" >&2
      return 1
    fi
    if ! wait_until 5 android_activity_resumed; then
      echo "Android active lifecycle gate failed in cycle $cycle: Activity did not resume" >&2
      return 1
    fi
    foreground_pid="$(android_app_pid)"
    if [[ "$foreground_pid" != "$before_pid" ]]; then
      echo "Android active lifecycle gate failed in cycle $cycle: app process restarted" >&2
      return 1
    fi
    if ! wait_until "$VPN_START_WAIT_SECS" vpn_active \
      || ! wait_for_android_runtime_state
    then
      echo "Android active lifecycle gate failed in cycle $cycle: VPN/runtime did not remain active" >&2
      return 1
    fi
    capture_android_vpn_link_stats "after-foreground-$cycle" || true
    if truthy "$TUN_PACKET_PROBE"; then
      if ! run_android_tun_packet_probe; then
        echo "Android active lifecycle gate failed in cycle $cycle: tunnel traffic failed" >&2
        return 1
      fi
      if ! cp \
          "$(android_tun_packet_probe_summary_path)" \
          "$RUNTIME_STATE_RESULT_DIR/mobile-android-tun-probe-after-foreground-$cycle-$$.json"
      then
        echo "Android active lifecycle gate failed in cycle $cycle: TUN receipt copy failed" >&2
        return 1
      fi
    fi
    if ! run_android_exit_network_probe "wireguard-exit-after-foreground-$cycle"; then
      echo "Android active lifecycle gate failed in cycle $cycle: DNS/HTTPS failed" >&2
      return 1
    fi
    if ! assert_single_android_app_process; then
      echo "Android active lifecycle gate failed in cycle $cycle: app process count changed" >&2
      return 1
    fi
    echo "Android active-VPN lifecycle cycle $cycle/$ANDROID_LIFECYCLE_CYCLES passed after >=${ANDROID_LIFECYCLE_BACKGROUND_DWELL_SECS}s background dwell"
  done
  echo "Android active-VPN background/foreground lifecycle gate passed: $ANDROID_LIFECYCLE_CYCLES cycles"
}

seed_debug_config() {
  if [[ "$create_network" == "1" || "$create_network" == "true" ]]; then
    start_main_activity \
      --es "$DEBUG_ACTION_EXTRA" add_network \
      --es "$DEBUG_NETWORK_NAME_EXTRA" "$DEBUG_NETWORK_NAME"
    sleep "$DEBUG_SEED_WAIT_SECS"
  fi

  if [[ -n "$DEBUG_EXIT_NODE" ]]; then
    start_main_activity \
      --es "$DEBUG_ACTION_EXTRA" set_fips_exit \
      --es "$DEBUG_EXIT_NODE_EXTRA" "$DEBUG_EXIT_NODE"
    sleep "$DEBUG_SEED_WAIT_SECS"
  fi

  if [[ -n "$DEBUG_WIREGUARD_CONFIG" || -n "$DEBUG_WIREGUARD_CONFIG_FILE" ]]; then
    local encoded
    encoded="$(wireguard_config | base64_no_wrap)"
    start_main_activity \
      --es "$DEBUG_ACTION_EXTRA" set_wireguard_exit \
      --es "$DEBUG_WIREGUARD_CONFIG_BASE64_EXTRA" "$encoded"
    sleep "$DEBUG_SEED_WAIT_SECS"
  fi

  if [[ -n "$EXIT_DNS_MODE" ]]; then
    if truthy "$EXIT_DNS_USE_SHIPPED_UI"; then
      configure_android_exit_dns_ui
    else
      configure_android_exit_dns_debug "dns-before-connect-$$-$(date +%s%N)"
    fi
  fi
}

dump_vpn_diagnostics() {
  echo "Android VPN cycle did not reach the expected service/network state." >&2
  echo "If this is a first run, approve the Android VPN permission prompt and retry." >&2
  echo "If this device has no active nvpn network, use --create-network or approve its signed join request first." >&2
  echo "NVPN_ANDROID_DEBUG_WIREGUARD_CONFIG_FILE only configures a WG exit; it does not create the required nvpn network." >&2
  echo >&2
  echo "---- dumpsys activity services $PACKAGE_NAME ----" >&2
  "$ADB" -s "$serial" shell dumpsys activity services "$PACKAGE_NAME" >&2 || true
  echo >&2
  echo "---- dumpsys connectivity VPN agents ----" >&2
  "$ADB" -s "$serial" shell dumpsys connectivity 2>/dev/null \
    | tr -d '\r' \
    | grep -E 'NetworkAgentInfo\{.*ni\{VPN|VpnNetworkProvider' >&2 || true
  echo >&2
  echo "---- recent NostrVpnService logcat ----" >&2
  "$ADB" -s "$serial" logcat -d -t 200 2>/dev/null \
    | tr -d '\r' \
    | grep -E 'NostrVpnService|fi.siriusbusiness.nvpn|org.nostrvpn.app|AndroidRuntime|ActivityTaskManager' >&2 || true
}

ADB="$(resolve_adb)"

if truthy "$RELEASE_BLACKBOX_GATE"; then
  android_release_require_inputs
fi

if [[ "$build" -eq 1 ]]; then
  if truthy "$RELEASE_BLACKBOX_GATE"; then
    "$ROOT/tools/run-android" release
  else
    "$ROOT/tools/run-android" build
  fi
fi

if [[ ! -f "$APK_PATH" ]]; then
  echo "Android APK not found at $APK_PATH" >&2
  exit 1
fi

serial="$(select_serial "$ADB")"
if [[ -z "$serial" ]]; then
  echo "No online Android device or emulator found; set NVPN_ANDROID_SERIAL or start an emulator" >&2
  exit 1
fi

"$ADB" -s "$serial" wait-for-device
remove_stale_nvpn_packages
if [[ "$install" -eq 1 ]]; then
  if "$ADB" -s "$serial" shell pm path "$CANONICAL_PACKAGE_NAME" >/dev/null 2>&1; then
    "$ADB" -s "$serial" shell am force-stop "$CANONICAL_PACKAGE_NAME" >/dev/null
  fi
  "$ADB" -s "$serial" install -r "$APK_PATH"
fi
PACKAGE_UID="$(resolve_package_uid "$ADB" "$serial")"
if [[ -z "$PACKAGE_UID" ]]; then
  echo "Could not resolve Android uid for installed package $PACKAGE_NAME" >&2
  exit 1
fi

if [[ "$clear_state" -eq 1 ]]; then
  "$ADB" -s "$serial" shell pm clear "$PACKAGE_NAME" >/dev/null
fi

if truthy "$RELEASE_BLACKBOX_GATE"; then
  verify_android_release_install
  start_main_activity
  "$ADB" -s "$serial" shell pm path "$PACKAGE_NAME" >/dev/null
  wait_until 10 android_app_process_running || {
    echo "Android Release app process did not start within 10 seconds" >&2
    exit 1
  }
  assert_single_android_app_process
  if [[ "$vpn_cycle" -eq 1 ]]; then
    run_android_release_blackbox_cycle
  else
    run_android_activity_lifecycle_gate
    if ! vpn_inactive; then
      echo "Android Release foreground idle CPU gate requires VPN-off state" >&2
      exit 1
    fi
    run_android_idle_cpu_gate "Android Release foreground VPN-off"
    write_android_release_foreground_idle_receipt
  fi
  assert_single_android_app_process
  echo "Android Release black-box smoke passed on adb serial: $serial"
  exit 0
fi

if [[ "$vpn_cycle" -eq 1 ]]; then
  grant_debug_runtime_permissions
fi

start_main_activity
"$ADB" -s "$serial" shell pm path "$PACKAGE_NAME" >/dev/null
wait_for_android_build_metadata
assert_single_android_app_process
if [[ "$vpn_cycle" -eq 0 ]]; then
  run_android_activity_lifecycle_gate
fi
assert_single_android_app_process

if [[ "$vpn_cycle" -eq 0 ]]; then
  run_android_idle_cpu_gate "Android foreground app"
fi

if [[ "$vpn_cycle" -eq 1 ]]; then
  seed_debug_config
  start_main_activity --es "$DEBUG_ACTION_EXTRA" disconnect
  if ! wait_until "$VPN_STOP_WAIT_SECS" vpn_inactive; then
    dump_vpn_diagnostics
    echo "Android smoke failed: VPN remained active after debug disconnect." >&2
    exit 1
  fi
  if ! run_android_direct_network_probe before-connect; then
    exit 1
  fi
  if truthy "$cleanup_after_vpn_cycle"; then
    vpn_cleanup_armed=1
  fi
  start_main_activity --es "$DEBUG_ACTION_EXTRA" connect
  maybe_accept_vpn_dialog
  if ! wait_until "$VPN_START_WAIT_SECS" vpn_active; then
    dump_vpn_diagnostics
    echo "Android smoke failed: VPN service and network did not become active after debug connect." >&2
    exit 1
  fi
  assert_single_android_app_process
  if ! wait_for_android_runtime_state; then
    dump_vpn_diagnostics
    echo "Android smoke failed: Rust mobile runtime state did not become fresh after debug connect." >&2
    exit 1
  fi
  capture_android_vpn_link_stats "after-connect" || true
  if ! run_android_tun_packet_probe; then
    dump_vpn_diagnostics
    echo "Android smoke failed: native TUN packet probe failed." >&2
    exit 1
  fi
  if ! run_android_exit_network_probe wireguard-exit; then
    dump_vpn_diagnostics
    exit 1
  fi
  if ! run_android_underlay_network_change_gate; then
    dump_vpn_diagnostics
    exit 1
  fi
  if truthy "$SWITCH_TO_DIRECT_WHILE_CONNECTED"; then
    select_android_direct_ui
    if ! wait_until "$VPN_START_WAIT_SECS" vpn_active; then
      dump_vpn_diagnostics
      echo "Android smoke failed: VPN service/network did not remain active after selecting Direct." >&2
      exit 1
    fi
    if ! wait_for_android_runtime_state; then
      dump_vpn_diagnostics
      echo "Android smoke failed: runtime did not remain active after selecting Direct." >&2
      exit 1
    fi
    if ! run_android_direct_while_tunnel_probe; then
      dump_vpn_diagnostics
      exit 1
    fi
  fi
  if ! run_android_active_vpn_lifecycle_gate; then
    dump_vpn_diagnostics
    exit 1
  fi
  if ! cleanup_android_vpn_after_pass; then
    exit 1
  fi
  assert_single_android_app_process
  if ! run_android_direct_network_probe after-disconnect; then
    exit 1
  fi
fi

echo "Android smoke passed on adb serial: $serial"
