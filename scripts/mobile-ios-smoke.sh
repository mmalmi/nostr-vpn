#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "$ROOT/scripts/release_common.sh"
# shellcheck disable=SC1091
source "$ROOT/scripts/mobile_env.sh"
source "$ROOT/scripts/lib-mobile-ios-lifecycle.sh"
load_release_env "$ROOT"
load_appstoreconnect_defaults
load_mobile_env "$ROOT"
resolve_shared_build_metadata "$ROOT"
export NVPN_IOS_BUNDLE_ID="${NVPN_IOS_BUNDLE_ID:-${NVPN_DEFAULT_IOS_BUNDLE_ID:-fi.siriusbusiness.nvpn}}"
export NVPN_IOS_PACKET_TUNNEL_BUNDLE_ID="${NVPN_IOS_PACKET_TUNNEL_BUNDLE_ID:-$NVPN_IOS_BUNDLE_ID.PacketTunnel}"
export NVPN_IOS_APP_GROUP_IDENTIFIER="${NVPN_IOS_APP_GROUP_IDENTIFIER:-group.$NVPN_IOS_BUNDLE_ID.shared}"
BUNDLE_ID="$NVPN_IOS_BUNDLE_ID"
SIMULATOR_NAME="${NVPN_IOS_SIMULATOR_NAME:-iPhone 17 Pro}"
PROJECT="$ROOT/ios/NostrVpnIos.xcodeproj"
SCHEME="${NVPN_IOS_SCHEME:-NostrVpnIos}"
DEVICE_CONFIGURATION="${NVPN_IOS_DEVICE_CONFIGURATION:-Debug}"
DEVICE_DERIVED_DATA="${NVPN_IOS_DEVICE_DERIVED_DATA:-$ROOT/ios/.build/DeviceDerivedData}"
DEVICE_DESTINATION="${NVPN_IOS_DEVICE_DESTINATION:-generic/platform=iOS}"
DEVICE_CODE_SIGN_IDENTITY="${NVPN_IOS_DEVICE_CODE_SIGN_IDENTITY:-Apple Development}"
DEVICE_SIGNING_MODE="${NVPN_IOS_DEVICE_SIGNING_MODE:-adhoc}"
DEVICE_SIGNING_PREPARED=0
DEVICE_PROVISIONING_DIR="${NVPN_IOS_DEVICE_PROVISIONING_DIR:-$ROOT/ios/.build/DeviceSigning}"
DEVICE_PROVISIONING_ENV="$DEVICE_PROVISIONING_DIR/provisioning.env"
INSTALL_DEVICE_APP="${NVPN_IOS_INSTALL:-0}"
CREATE_NETWORK="${NVPN_IOS_DEBUG_CREATE_NETWORK:-0}"
DEBUG_NETWORK_NAME="${NVPN_IOS_DEBUG_NETWORK_NAME:-iOS smoke}"
VPN_START_WAIT_SECS="${NVPN_IOS_VPN_START_WAIT_SECS:-12}"
VPN_RESULT_WAIT_SECS="${NVPN_IOS_VPN_RESULT_WAIT_SECS:-12}"
VPN_RESULT_NAME="${NVPN_IOS_VPN_RESULT_NAME:-mobile-ios-smoke-vpn-$$.json}"
VPN_RESULT_DIR="${NVPN_IOS_RESULT_DIR:-$ROOT/artifacts/mobile-ios}"
IOS_IDLE_CPU_RESULT_NAME="${NVPN_IOS_IDLE_CPU_RESULT_NAME:-mobile-ios-idle-cpu-$$.json}"
TUN_PACKET_PROBE_SUMMARY_NAME="${NVPN_IOS_TUN_PACKET_PROBE_SUMMARY_NAME:-mobile-ios-tun-probe-summary-$$.json}"
TUN_PACKET_PROBE_TARGET="${NVPN_IOS_TUN_PACKET_PROBE_TARGET:-10.44.255.254}"
TUN_PACKET_PROBE_PORT="${NVPN_IOS_TUN_PACKET_PROBE_PORT:-9}"
TUN_PACKET_PROBE_COUNT="${NVPN_IOS_TUN_PACKET_PROBE_COUNT:-4}"
TUN_PACKET_PROBE_WAIT_SECS="${NVPN_IOS_TUN_PACKET_PROBE_WAIT_SECS:-6}"
TUN_PACKET_PROBE_REQUIRE_REPLY="${NVPN_IOS_TUN_PACKET_PROBE_REQUIRE_REPLY:-0}"
DEBUG_WIREGUARD_CONFIG="${NVPN_IOS_DEBUG_WIREGUARD_CONFIG:-}"
DEBUG_WIREGUARD_CONFIG_FILE="${NVPN_IOS_DEBUG_WIREGUARD_CONFIG_FILE:-}"
EXIT_PROBE_HOST="${NVPN_IOS_EXIT_PROBE_HOST:-}"
EXIT_PROBE_EXPECTED_IP="${NVPN_IOS_EXIT_PROBE_EXPECTED_IP:-}"
EXIT_PROBE_URL="${NVPN_IOS_EXIT_PROBE_URL:-}"
EXPECTED_EXIT_SOURCE_IP="${NVPN_IOS_EXPECTED_EXIT_SOURCE_IP:-}"
DIRECT_PROBE_HOST="${NVPN_IOS_DIRECT_PROBE_HOST:-example.com}"
DIRECT_PROBE_URL="${NVPN_IOS_DIRECT_PROBE_URL:-https://example.com/}"
EXIT_DNS_MODE="${NVPN_IOS_EXIT_DNS_MODE:-}"
EXIT_DNS_DOH_PROVIDER="${NVPN_IOS_EXIT_DNS_DOH_PROVIDER:-cloudflare}"
EXIT_DNS_CUSTOM_DOH_URL="${NVPN_IOS_EXIT_DNS_CUSTOM_DOH_URL:-}"
EXIT_DNS_CUSTOM_DOH_BOOTSTRAP_IPS="${NVPN_IOS_EXIT_DNS_CUSTOM_DOH_BOOTSTRAP_IPS:-}"
EXIT_DNS_THROUGH_EXIT_SERVERS="${NVPN_IOS_EXIT_DNS_THROUGH_EXIT_SERVERS:-}"
EXIT_DNS_USE_SHIPPED_UI="${NVPN_IOS_EXIT_DNS_USE_SHIPPED_UI:-0}"
EXPECT_DEBUG_DNS_INJECTED="${NVPN_IOS_EXPECT_DEBUG_DNS_INJECTED:-}"
SWITCH_TO_DIRECT_WHILE_CONNECTED="${NVPN_IOS_SWITCH_TO_DIRECT_WHILE_CONNECTED:-0}"
EXPECT_WIREGUARD_EXIT="${NVPN_IOS_EXPECT_WIREGUARD_EXIT:-0}"
EXPECTED_WIREGUARD_ENDPOINT="${NVPN_IOS_EXPECT_WIREGUARD_ENDPOINT:-}"
VERIFY_DIRECT_RESTORATION="${NVPN_IOS_VERIFY_DIRECT_RESTORATION:-0}"
cleanup_after_vpn_cycle="${NVPN_IOS_CLEANUP_AFTER_VPN_CYCLE:-1}"
IDLE_CPU_GATE="${NVPN_IOS_IDLE_CPU_GATE:-${NVPN_IDLE_CPU_GATE:-1}}"
IDLE_CPU_MAX_PERCENT="${NVPN_IOS_IDLE_CPU_MAX_PERCENT:-${NVPN_IDLE_CPU_MAX_PERCENT:-5}}"
IDLE_CPU_SAMPLE_SECONDS="${NVPN_IOS_IDLE_CPU_SAMPLE_SECONDS:-${NVPN_IDLE_CPU_SAMPLE_SECONDS:-10}}"
IDLE_CPU_SETTLE_SECONDS="${NVPN_IOS_IDLE_CPU_SETTLE_SECONDS:-${NVPN_IDLE_CPU_SETTLE_SECONDS:-3}}"
IOS_SIM_PROCESS_NAME="${NVPN_IOS_SIM_PROCESS_NAME:-Nostr VPN}"
IOS_SIMULATOR_UI_GATE="${NVPN_IOS_SIMULATOR_UI_GATE:-1}"
IOS_LIFECYCLE_GATE="${NVPN_IOS_LIFECYCLE_GATE:-1}"
IOS_LIFECYCLE_CYCLES="${NVPN_IOS_LIFECYCLE_CYCLES:-3}"
IOS_ACTIVE_TUNNEL_LIFECYCLE_CYCLES="${NVPN_IOS_ACTIVE_TUNNEL_LIFECYCLE_CYCLES:-3}"
SCREENSHOT="$ROOT/artifacts/nostr-vpn-ios.png"
vpn_cleanup_armed=0
vpn_cleanup_device=""

usage() {
  cat >&2 <<'EOF'
usage: scripts/mobile-ios-smoke.sh [simulator|device] [--install] [--disconnect] [--create-network] [--vpn-cycle] [--device DEVICE] [--leave-vpn-active] [--probe-target IP] [--probe-port PORT] [--probe-count N] [--probe-require-reply]

simulator  Builds, clean-installs, launches, screenshots, samples idle CPU,
           and drives QR, DNS-settings, and lifecycle controls through XCTest.
device     Launches an already installed physical test build.
           By default, switches to a system app and back three times and proves
           the shared native core closes and reopens on every real transition,
           including a ten-second suspended interval per cycle.
--install  Builds and installs the current iphoneos test app
           before launching device mode.
--disconnect
           Confirm that the installed physical test app's packet tunnel is off,
           then exit without running a smoke.
--device DEVICE
           Selects the physical device identifier for this run. Equivalent to
           NVPN_IOS_DEVICE=DEVICE.
--create-network
           Creates a local debug network before the device VPN cycle, for OS
           Packet Tunnel coverage without peer dataplane coverage.
--leave-vpn-active
           Preserve a passing VPN cycle for manual inspection. By default a
           passing --vpn-cycle asks the debug app to disconnect afterwards.

Physical-device mode uses NVPN_IOS_DEVICE/NVPN_IOS_DEVICE_ID when set, or auto-
selects the only connected physical iPhone/iPad. Values may live in
.env.mobile.local or shell env. Keep device identifiers and signing details out
of committed files.

Simulator mode drives the shipped UI and native app core, but iOS Packet Tunnel
dataplane checks still need a physical device. First-run VPN/profile permission
prompts may need a manual approval before --vpn-cycle can run unattended.

Device install mode requires signing access for NVPN_IOS_BUNDLE_ID and
NVPN_IOS_PACKET_TUNNEL_BUNDLE_ID. When App Store Connect credentials are
available, physical gates use company Ad Hoc profiles and fail if those profiles
cannot be prepared. Set
NVPN_IOS_DEVICE_SIGNING_MODE=development only for Xcode-managed development;
that mode may require explicitly trusting its development certificate. Set
NVPN_IOS_TEAM_ID in the shell or local env file.

The physical-device packet probe defaults to 4 UDP packets toward the debug
non-local tunnel probe target. Use --probe-target, --probe-port, --probe-count,
and --probe-require-reply for a reachable peer row that requires native TUN write
counters to increase. NVPN_IOS_TUN_PACKET_PROBE_WAIT_SECS still controls the
observation window.

Set NVPN_IOS_DEBUG_WIREGUARD_CONFIG_FILE with NVPN_IOS_EXIT_PROBE_HOST,
NVPN_IOS_EXIT_PROBE_EXPECTED_IP, and NVPN_IOS_EXIT_PROBE_URL for a real exit
probe. NVPN_IOS_VERIFY_DIRECT_RESTORATION=1 additionally requires native DNS
and HTTPS before connect and after the packet tunnel is fully disconnected.
Set NVPN_IOS_EXIT_DNS_MODE and its provider/custom/through-exit companion
variables to dispatch the production Exit DNS settings action before starting
the real Packet Tunnel. Set NVPN_IOS_EXIT_DNS_USE_SHIPPED_UI=1 after a shipped
UI test saves those values; the packet probe then treats them as expectations
without injecting them. NVPN_IOS_SWITCH_TO_DIRECT_WHILE_CONNECTED=1 runs a
physical XCTest that taps This device in the shipped Internet-source picker,
verifies the installed tunnel config has neither a default route nor WireGuard
exit, and proves DNS and HTTPS while the OS VPN stays connected.
With a VPN cycle, the lifecycle gate uses direct CoreDevice app activation for
three ten-second background cycles by default and requires a fresh real
TUN/DNS/HTTPS/endpoint receipt after every foreground before continuing. It
does not depend on the device's UI Automation mode.
EOF
}

mode="${1:-simulator}"
if [[ $# -gt 0 ]]; then
  shift
fi
vpn_cycle=0
disconnect_only=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --install)
      INSTALL_DEVICE_APP=1
      ;;
    --disconnect)
      disconnect_only=1
      ;;
    --create-network)
      CREATE_NETWORK=1
      ;;
    --device)
      if [[ $# -lt 2 ]]; then
        echo "--device requires a value" >&2
        exit 2
      fi
      export NVPN_IOS_DEVICE="$2"
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
    --probe-port)
      if [[ $# -lt 2 ]]; then
        echo "--probe-port requires a value" >&2
        exit 2
      fi
      TUN_PACKET_PROBE_PORT="$2"
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
    --probe-require-reply)
      TUN_PACKET_PROBE_REQUIRE_REPLY=1
      ;;
    --leave-vpn-active)
      cleanup_after_vpn_cycle=0
      ;;
    --vpn-cycle)
      vpn_cycle=1
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

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "iOS smoke requires macOS with Xcode" >&2
  exit 1
fi

run_simulator() {
  "$ROOT/tools/run-ios" run
  if [[ ! -s "$SCREENSHOT" ]]; then
    echo "Expected simulator screenshot at $SCREENSHOT" >&2
    exit 1
  fi
  run_ios_simulator_idle_cpu_gate
  run_ios_simulator_ui_gate
  echo "iOS simulator smoke passed: $SCREENSHOT"
}

ios_sim_device_id() {
  local booted
  booted="$(xcrun simctl list devices available \
    | sed -n 's/.*iPhone[^()]*(\([0-9A-F-]\{36\}\)) (Booted).*/\1/p' \
    | head -n 1)"
  if [[ -n "$booted" ]]; then
    printf '%s\n' "$booted"
    return
  fi
  xcrun simctl list devices available \
    | sed -n "s/.*$SIMULATOR_NAME (\([0-9A-F-]\{36\}\)).*/\1/p" \
    | head -n 1
}

ios_simulator_app_pid() {
  local device="$1"
  ps -axo pid=,command= \
    | awk -v device="$device" -v app="$IOS_SIM_PROCESS_NAME.app/$IOS_SIM_PROCESS_NAME" '
        !pid && index($0, device) && index($0, app) { pid = $1 }
        END { if (pid) print pid }
      '
}

run_ios_simulator_ui_gate() {
  if ! bool_is_true "$IOS_SIMULATOR_UI_GATE"; then
    echo "Skipping iOS simulator UI gate because NVPN_IOS_SIMULATOR_UI_GATE=$IOS_SIMULATOR_UI_GATE"
    return
  fi

  local device
  device="$(ios_sim_device_id)"
  if [[ -z "$device" ]]; then
    echo "iOS simulator UI gate failed: no simulator device id found" >&2
    return 1
  fi

  xcodebuild \
    -quiet \
    -project "$PROJECT" \
    -scheme "$SCHEME" \
    -configuration Debug \
    -derivedDataPath "$ROOT/ios/.build/DerivedData" \
    -destination "platform=iOS Simulator,id=$device" \
    -only-testing:NostrVpnIosUITests/NostrVpnIosUITests/testJoinRequestUsesFullWidthAndSurvivesBackgrounding \
    -only-testing:NostrVpnIosUITests/NostrVpnIosUITests/testExitDnsSettingsUseShippedControlsAndValidateRequiredFields \
    test
  echo "iOS simulator shipped-UI QR, DNS, and lifecycle gate passed"
}

run_ios_simulator_idle_cpu_gate() {
  case "$IDLE_CPU_GATE" in
    0|false|FALSE|False|no|NO|No|off|OFF|Off)
      echo "Skipping iOS simulator idle CPU gate because NVPN_IOS_IDLE_CPU_GATE=$IDLE_CPU_GATE"
      return
      ;;
  esac

  local device pid result_path
  device="$(ios_sim_device_id)"
  if [[ -z "$device" ]]; then
    echo "iOS simulator idle CPU gate failed: no simulator device id found" >&2
    exit 1
  fi
  pid="$(ios_simulator_app_pid "$device" | head -n 1)"
  if [[ -z "$pid" ]]; then
    echo "iOS simulator idle CPU gate failed: process $IOS_SIM_PROCESS_NAME not found on simulator $device" >&2
    exit 1
  fi
  mkdir -p "$VPN_RESULT_DIR"
  result_path="$VPN_RESULT_DIR/mobile-ios-simulator-idle-cpu-$$.json"
  "$ROOT/scripts/idle-cpu-gate.py" host-pid \
    --pid "$pid" \
    --label "iOS simulator app" \
    --artifact "$result_path" \
    --max-percent "$IDLE_CPU_MAX_PERCENT" \
    --sample-seconds "$IDLE_CPU_SAMPLE_SECONDS" \
    --settle-seconds "$IDLE_CPU_SETTLE_SECONDS"
}

launch_device() {
  local device="$1"
  shift
  ios_device_launch "$device" "$BUNDLE_ID" "$@"
}

device_app_path() {
  find "$DEVICE_DERIVED_DATA/Build/Products/$DEVICE_CONFIGURATION-iphoneos" \
    -maxdepth 1 -name '*.app' -type d | sort | head -n 1
}

connected_ios_udid() {
  local device="$1"
  resolve_physical_ios_udid "$device"
}

prepare_device_signing() {
  local device="$1"
  if [[ "$DEVICE_SIGNING_PREPARED" -eq 1 ]]; then
    return 0
  fi

  local mode="$DEVICE_SIGNING_MODE"

  case "$mode" in
    adhoc)
      local udid profile_log
      udid="$(connected_ios_udid "$device")"
      mkdir -p "$DEVICE_PROVISIONING_DIR"
      profile_log="$DEVICE_PROVISIONING_DIR/ios-profiles.log"
      if ! NVPN_IOS_PROFILE_TYPE=IOS_APP_ADHOC \
        NVPN_IOS_PROFILE_NAME="Nostr VPN Ad Hoc main physical gate" \
        NVPN_IOS_PACKET_TUNNEL_PROFILE_NAME="Nostr VPN Ad Hoc packet tunnel physical gate" \
        NVPN_IOS_CODE_SIGN_IDENTITY="Apple Distribution" \
        NVPN_IOS_DEVICE_UDIDS="$udid" \
        NVPN_IOS_PROFILES_ENV_PATH="$DEVICE_PROVISIONING_ENV" \
        "$ROOT/scripts/ios-profiles" ensure >"$profile_log" 2>&1
      then
        echo "Unable to prepare company Ad Hoc signing; private details are in $profile_log" >&2
        return 1
      fi
      # shellcheck disable=SC1090
      source "$DEVICE_PROVISIONING_ENV"
      : "${NVPN_IOS_CODE_SIGN_IDENTITY:?Ad Hoc signing identity not set}"
      : "${NVPN_IOS_PROVISIONING_PROFILE_UUID:?Ad Hoc app profile not set}"
      : "${NVPN_IOS_PACKET_TUNNEL_PROVISIONING_PROFILE_UUID:?Ad Hoc tunnel profile not set}"
      DEVICE_CONFIGURATION="DeviceDebug"
      DEVICE_CODE_SIGN_IDENTITY="$NVPN_IOS_CODE_SIGN_IDENTITY"
      echo "Using company Ad Hoc signing for the physical iOS gate (no development-certificate trust required)."
      ;;
    development)
      DEVICE_CONFIGURATION="${NVPN_IOS_DEVICE_CONFIGURATION:-Debug}"
      DEVICE_CODE_SIGN_IDENTITY="${NVPN_IOS_DEVICE_CODE_SIGN_IDENTITY:-Apple Development}"
      echo "Using Xcode development signing for the physical iOS gate."
      ;;
    *)
      echo "NVPN_IOS_DEVICE_SIGNING_MODE must be adhoc or development (got $mode)." >&2
      return 2
      ;;
  esac
  DEVICE_SIGNING_MODE="$mode"
  DEVICE_SIGNING_PREPARED=1
}

build_device_app() {
  local device="$1"
  local team="${NVPN_IOS_TEAM_ID:-}"
  if [[ -z "$team" ]]; then
    echo "Set NVPN_IOS_TEAM_ID to build/install a physical iOS device app." >&2
    exit 1
  fi

  prepare_device_signing "$device"

  "$ROOT/tools/run-ios" xcframework
  "$ROOT/tools/run-ios" project

  local cmd=(xcodebuild)
  if bool_is_true "${NVPN_IOS_XCODEBUILD_QUIET:-1}"; then
    cmd+=(-quiet)
  fi
  if bool_is_true "${NVPN_IOS_ALLOW_PROVISIONING_UPDATES:-1}"; then
    cmd+=(-allowProvisioningUpdates)
  fi
  cmd+=(
    -project "$PROJECT"
    -scheme "$SCHEME"
    -configuration "$DEVICE_CONFIGURATION"
    -derivedDataPath "$DEVICE_DERIVED_DATA"
    -destination "$DEVICE_DESTINATION"
    DEVELOPMENT_TEAM="$team"
    NVPN_BUILD_GIT_SHA="$NVPN_BUILD_GIT_SHA"
    NVPN_BUILD_TIMESTAMP_UTC="$NVPN_BUILD_TIMESTAMP_UTC"
  )
  if [[ "$DEVICE_SIGNING_MODE" == "adhoc" ]]; then
    cmd+=(
      NVPN_IOS_CODE_SIGN_IDENTITY="$DEVICE_CODE_SIGN_IDENTITY"
      NVPN_IOS_PROVISIONING_PROFILE_UUID="$NVPN_IOS_PROVISIONING_PROFILE_UUID"
      NVPN_IOS_PACKET_TUNNEL_PROVISIONING_PROFILE_UUID="$NVPN_IOS_PACKET_TUNNEL_PROVISIONING_PROFILE_UUID"
    )
  else
    cmd+=(CODE_SIGN_IDENTITY="$DEVICE_CODE_SIGN_IDENTITY")
  fi
  cmd+=(build)
  "${cmd[@]}"
}

install_device_app() {
  local device="$1"
  local app_path
  disconnect_ios_vpn_before_install "$device"
  build_device_app "$device"
  app_path="$(device_app_path)"
  if [[ -z "$app_path" ]]; then
    echo "Built iOS device app not found under $DEVICE_DERIVED_DATA" >&2
    exit 1
  fi
  xcrun devicectl device install app --device "$device" "$app_path" --quiet
}

device_app_is_installed() {
  local device="$1"
  xcrun devicectl device info apps --device "$device" 2>/dev/null \
    | awk -v bundle="$BUNDLE_ID" '$0 ~ bundle { found = 1 } END { exit !found }'
}

ios_main_app_process_ids() {
  local device="$1"
  local process_json
  process_json="$(mktemp "${TMPDIR:-/tmp}/nvpn-ios-processes.XXXXXX")"
  if ! xcrun devicectl device info processes \
    --device "$device" \
    --json-output "$process_json" \
    --quiet
  then
    rm -f "$process_json"
    return 1
  fi
  python3 - "$process_json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    payload = json.load(handle)


def visit(value):
    if isinstance(value, dict):
        executable = str(value.get("executable", ""))
        process_id = value.get("processIdentifier")
        if (
            executable.endswith("/Nostr%20VPN.app/Nostr%20VPN")
            or executable.endswith("/Nostr VPN.app/Nostr VPN")
        ) and isinstance(process_id, int):
            print(process_id)
        for child in value.values():
            visit(child)
    elif isinstance(value, list):
        for child in value:
            visit(child)


visit(payload)
PY
  rm -f "$process_json"
}

terminate_ios_app_processes_before_install() {
  local device="$1"
  local process_ids process_id ignored
  process_ids="$(ios_main_app_process_ids "$device")" || return 1
  while IFS= read -r process_id; do
    [[ -n "$process_id" ]] || continue
    xcrun devicectl device process terminate \
      --device "$device" \
      --pid "$process_id" \
      --quiet
  done <<<"$process_ids"
  for ignored in $(seq 1 20); do
    process_ids="$(ios_main_app_process_ids "$device")" || return 1
    if [[ -z "$process_ids" ]]; then
      return 0
    fi
    sleep 0.25
  done
  echo "iOS app process did not terminate before replacement" >&2
  return 1
}

copy_ios_disconnect_result() {
  local device="$1"
  local result_name="$2"
  local destination="$3"
  rm -f "$destination"
  xcrun devicectl device copy from \
    --device "$device" \
    --domain-type appDataContainer \
    --domain-identifier "$BUNDLE_ID" \
    --source "Library/Application Support/Nostr VPN Debug Results/$result_name" \
    --destination "$destination" \
    --quiet
}

validate_ios_disconnect_result() {
  python3 - "$1" <<'PY'
import json, sys

with open(sys.argv[1], encoding="utf-8") as fh:
    result = json.load(fh)
status = result.get("packetTunnelStatusRawValue")
if result.get("ok") is not True or not isinstance(status, int) or status > 1:
    raise SystemExit(1)
PY
}

disconnect_ios_vpn_confirmed() {
  local device="$1"
  local result_name="mobile-ios-disconnect-$$-$(date +%s).json"
  local destination="${TMPDIR:-/tmp}/$result_name"
  if ! launch_device "$device" --nvpn-debug-disconnect-result "$result_name" >/dev/null; then
    echo "iOS VPN cleanup failed: debug disconnect launch failed" >&2
    return 1
  fi
  local ignored
  for ignored in $(seq 1 20); do
    sleep 0.5
    if copy_ios_disconnect_result "$device" "$result_name" "$destination" 2>/dev/null \
      && validate_ios_disconnect_result "$destination"
    then
      rm -f "$destination"
      echo "iOS VPN cleanup verified: packet tunnel is disconnected"
      return 0
    fi
  done
  rm -f "$destination"
  echo "iOS VPN cleanup failed: packet tunnel did not confirm disconnection" >&2
  return 1
}

disconnect_ios_vpn_before_install() {
  local device="$1"
  if ! device_app_is_installed "$device"; then
    return 0
  fi
  if ! disconnect_ios_vpn_confirmed "$device"; then
    echo "Refusing to replace $BUNDLE_ID while its existing packet tunnel may still be active." >&2
    echo "Disconnect it in iOS Settings or trust/launch the installed development app, then retry." >&2
    return 1
  fi
  if ! terminate_ios_app_processes_before_install "$device"; then
    echo "Refusing to replace $BUNDLE_ID while an old app process is still running." >&2
    return 1
  fi
}

copy_vpn_probe_result() {
  local device="$1"
  local result_path="$VPN_RESULT_DIR/$VPN_RESULT_NAME"
  mkdir -p "$VPN_RESULT_DIR"
  rm -f "$result_path"
  if ! xcrun devicectl device copy from \
    --device "$device" \
    --domain-type appDataContainer \
    --domain-identifier "$BUNDLE_ID" \
    --source "Library/Application Support/Nostr VPN Debug Results/$VPN_RESULT_NAME" \
    --destination "$result_path" \
    --quiet
  then
    echo "Failed to copy the current iOS VPN probe receipt for $BUNDLE_ID" >&2
    echo "If this is a first run, approve the iOS VPN configuration prompt on the device and retry." >&2
    return 1
  fi
  if [[ ! -s "$result_path" ]]; then
    echo "iOS VPN probe result not found at $result_path" >&2
    return 1
  fi
  printf '%s\n' "$result_path"
}

vpn_probe_result_finished() {
  python3 - "$1" <<'PY'
import json
import sys

try:
    with open(sys.argv[1], encoding="utf-8") as handle:
        result = json.load(handle)
except (OSError, json.JSONDecodeError):
    raise SystemExit(1)
raise SystemExit(0 if result.get("phase") == "finished" and result.get("finishedAt") else 1)
PY
}

wait_for_vpn_probe_result() {
  local device="$1"
  local deadline="$((SECONDS + VPN_RESULT_WAIT_SECS))"
  local result_path=""
  while true; do
    if result_path="$(copy_vpn_probe_result "$device" 2>/dev/null)" \
      && vpn_probe_result_finished "$result_path"
    then
      printf '%s\n' "$result_path"
      return 0
    fi
    if (( SECONDS >= deadline )); then
      break
    fi
    sleep 0.5
  done

  # Return the latest partial receipt to the validator so it reports the exact
  # unfinished phase rather than collapsing a real transition hang into a
  # generic missing-file error.
  if [[ -n "$result_path" && -s "$result_path" ]]; then
    printf '%s\n' "$result_path"
    return 0
  fi
  copy_vpn_probe_result "$device"
}

copy_ios_debug_logs() {
  local device="$1"
  local stem="${VPN_RESULT_NAME%.json}"
  local copied=0
  mkdir -p "$VPN_RESULT_DIR"
  for name in app-debug.log nvpn-pkt-debug.log; do
    local destination="$VPN_RESULT_DIR/$stem-$name"
    rm -f "$destination"
    launch_device "$device" \
      --nvpn-debug-export-support-file "$name" \
      --nvpn-debug-export-result "$name" >/dev/null 2>&1 || continue
    sleep 0.5
    if xcrun devicectl device copy from \
      --device "$device" \
      --domain-type appDataContainer \
      --domain-identifier "$BUNDLE_ID" \
      --source "Library/Application Support/Nostr VPN Debug Results/$name" \
      --destination "$destination" \
      --quiet \
      2>/dev/null
    then
      if [[ -s "$destination" ]]; then
        echo "Copied iOS debug log: $destination" >&2
        copied=1
      else
        rm -f "$destination"
      fi
    else
      rm -f "$destination"
    fi
  done
  if [[ "$copied" -eq 1 ]]; then
    return 0
  fi
  return 1
}

validate_vpn_probe_result() {
  local result_path="$1"
  local summary_path="$VPN_RESULT_DIR/$TUN_PACKET_PROBE_SUMMARY_NAME"
  python3 "$ROOT/scripts/validate-mobile-ios-vpn-probe.py" \
    "$result_path" "$summary_path" "$NVPN_BUILD_GIT_SHA" \
    "$TUN_PACKET_PROBE_REQUIRE_REPLY" "$EXIT_PROBE_EXPECTED_IP" \
    "$VERIFY_DIRECT_RESTORATION" \
    "$EXIT_DNS_MODE" "$EXIT_DNS_DOH_PROVIDER" \
    "$EXIT_DNS_CUSTOM_DOH_URL" "$EXIT_DNS_CUSTOM_DOH_BOOTSTRAP_IPS" \
    "$EXIT_DNS_THROUGH_EXIT_SERVERS" "$SWITCH_TO_DIRECT_WHILE_CONNECTED" \
    "$EXPECT_WIREGUARD_EXIT" "$EXPECT_DEBUG_DNS_INJECTED" \
    "$IOS_LIFECYCLE_GATE" "$IOS_ACTIVE_TUNNEL_LIFECYCLE_CYCLES" \
    "$EXPECTED_WIREGUARD_ENDPOINT" "$EXIT_PROBE_HOST" "$EXIT_PROBE_URL" \
    "$EXPECTED_EXIT_SOURCE_IP"
}

run_ios_device_idle_cpu_gate() {
  local device="$1"
  local process_pattern="$2"
  local label="$3"
  case "$IDLE_CPU_GATE" in
    0|false|FALSE|False|no|NO|No|off|OFF|Off)
      echo "Skipping iOS physical-device idle CPU gate because NVPN_IOS_IDLE_CPU_GATE=$IDLE_CPU_GATE"
      return
      ;;
  esac
  local process result_path timeout_seconds
  case "$process_pattern" in
    '^Nostr VPN Tunnel$') process="packet-tunnel" ;;
    '^Nostr VPN$') process="app" ;;
    *)
      echo "Unsupported iOS idle CPU process pattern: $process_pattern" >&2
      return 2
      ;;
  esac
  mkdir -p "$VPN_RESULT_DIR"
  result_path="$VPN_RESULT_DIR/$IOS_IDLE_CPU_RESULT_NAME"
  timeout_seconds="$(python3 - "$IDLE_CPU_SETTLE_SECONDS" "$IDLE_CPU_SAMPLE_SECONDS" <<'PY'
import math
import sys

print(math.ceil(float(sys.argv[1]) + float(sys.argv[2]) + 20))
PY
)"
  launch_device "$device" \
    --nvpn-debug-idle-cpu-probe \
    --nvpn-debug-idle-cpu-result "$IOS_IDLE_CPU_RESULT_NAME" \
    --nvpn-debug-idle-cpu-process "$process" \
    --nvpn-debug-idle-cpu-max-percent "$IDLE_CPU_MAX_PERCENT" \
    --nvpn-debug-idle-cpu-sample-seconds "$IDLE_CPU_SAMPLE_SECONDS" \
    --nvpn-debug-idle-cpu-settle-seconds "$IDLE_CPU_SETTLE_SECONDS" >/dev/null

  local ignored
  for ignored in $(seq 1 $((timeout_seconds * 2))); do
    sleep 0.5
    if ! copy_ios_disconnect_result \
      "$device" "$IOS_IDLE_CPU_RESULT_NAME" "$result_path" 2>/dev/null
    then
      continue
    fi
    if python3 - "$result_path" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    result = json.load(handle)
raise SystemExit(0 if result.get("phase") == "finished" else 1)
PY
    then
      break
    fi
  done

  python3 - \
    "$result_path" "$process" "$label" "$IDLE_CPU_MAX_PERCENT" \
    "$IDLE_CPU_SAMPLE_SECONDS" "$NVPN_BUILD_GIT_SHA" <<'PY'
import json
import math
import sys

path, process, label, maximum, sample_seconds, git_sha = sys.argv[1:]
with open(path, encoding="utf-8") as handle:
    result = json.load(handle)
maximum = float(maximum)
sample_seconds = float(sample_seconds)
errors = []
for key, expected in (
    ("phase", "finished"),
    ("process", process),
    ("label", label),
    ("appBuildGitSha", git_sha),
):
    if result.get(key) != expected:
        errors.append(f"{key}={result.get(key)!r}, expected {expected!r}")
cpu = result.get("cpuPercent")
elapsed = result.get("elapsedSeconds")
if result.get("ok") is not True:
    errors.append(f"ok={result.get('ok')!r} error={result.get('error')!r}")
if not isinstance(result.get("pid"), int) or result["pid"] <= 0:
    errors.append(f"pid={result.get('pid')!r}")
if not isinstance(cpu, (int, float)) or not math.isfinite(cpu) or cpu < 0 or cpu > maximum:
    errors.append(f"cpuPercent={cpu!r}, maximum={maximum!r}")
if not isinstance(elapsed, (int, float)) or elapsed < sample_seconds * 0.95:
    errors.append(f"elapsedSeconds={elapsed!r}, sampleSeconds={sample_seconds!r}")
if errors:
    raise SystemExit("iOS idle CPU receipt failed: " + "; ".join(errors))
print(f"{label} idle CPU ok: {cpu:.3f}% <= {maximum:.3f}%")
print(f"Result: {path}")
PY
}

run_ios_connected_direct_ui_driver() {
  local device="$1"
  shift
  local destination_udid
  destination_udid="$(resolve_physical_ios_udid "$device")"
  local team="${NVPN_IOS_TEAM_ID:-}"
  if [[ -z "$team" ]]; then
    echo "Set NVPN_IOS_TEAM_ID to run the physical iOS Direct UI gate." >&2
    return 1
  fi
  prepare_device_signing "$device"

  local arguments_base64 run_id log marker
  arguments_base64="$(python3 - "$@" <<'PY'
import base64
import json
import sys

print(base64.b64encode(json.dumps(sys.argv[1:]).encode()).decode())
PY
  )"
  run_id="connected-direct-ui-$$-$RANDOM-$(date +%s)"
  mkdir -p "$VPN_RESULT_DIR"
  log="$VPN_RESULT_DIR/mobile-ios-connected-direct-ui-$$.log"
  marker="$VPN_RESULT_DIR/mobile-ios-connected-direct-markers-$$.log"

  local -a command=(
    xcodebuild
    -quiet
    -allowProvisioningUpdates
    -project "$PROJECT"
    -scheme "$SCHEME"
    -configuration "$DEVICE_CONFIGURATION"
    -derivedDataPath "$DEVICE_DERIVED_DATA"
    -destination "platform=iOS,id=$destination_udid"
    -destination-timeout 60
    -collect-test-diagnostics never
    -only-testing:NostrVpnIosUITests/NostrVpnIosUITests/testSelectDirectWhilePhysicalTunnelConnected
    DEVELOPMENT_TEAM="$team"
  )
  if [[ "$DEVICE_SIGNING_MODE" == "adhoc" ]]; then
    command+=(
      NVPN_IOS_CODE_SIGN_IDENTITY="$DEVICE_CODE_SIGN_IDENTITY"
      NVPN_IOS_PROVISIONING_PROFILE_UUID="$NVPN_IOS_PROVISIONING_PROFILE_UUID"
      NVPN_IOS_PACKET_TUNNEL_PROVISIONING_PROFILE_UUID="$NVPN_IOS_PACKET_TUNNEL_PROVISIONING_PROFILE_UUID"
    )
  else
    command+=(CODE_SIGN_IDENTITY="$DEVICE_CODE_SIGN_IDENTITY")
  fi
  if [[
    -n "${NVPN_ASC_AUTH_KEY_PATH:-}" &&
    -n "${NVPN_ASC_AUTH_KEY_ID:-}" &&
    -n "${NVPN_ASC_AUTH_KEY_ISSUER_ID:-}"
  ]]; then
    command+=(
      -authenticationKeyPath "$NVPN_ASC_AUTH_KEY_PATH"
      -authenticationKeyID "$NVPN_ASC_AUTH_KEY_ID"
      -authenticationKeyIssuerID "$NVPN_ASC_AUTH_KEY_ISSUER_ID"
    )
  fi
  command+=(
    NVPN_XCUITEST_RUN_ID="$run_id"
    NVPN_XCUITEST_CONNECTED_DIRECT_GATE=1
    NVPN_XCUITEST_APP_LAUNCH_ARGS_BASE64="$arguments_base64"
    test
  )
  if ! NSUnbufferedIO=YES "${command[@]}" >"$log" 2>&1; then
    tail -n 120 "$log" >&2
    echo "The iOS lifecycle runner failed; enter the VPN-approval passcode if shown, otherwise verify UI Automation." >&2
    return 1
  fi

  rm -f "$marker"
  xcrun devicectl device copy from \
    --device "$device" \
    --domain-type appDataContainer \
    --domain-identifier "$BUNDLE_ID.UITests.xctrunner" \
    --source "Documents/nvpn-ui-gate-markers.log" \
    --destination "$marker" \
    --quiet >/dev/null
  grep -Fxq "NVPN_XCUITEST_RUN_ID=$run_id" "$marker" \
    && grep -Fxq "NVPN_CONNECTED_DIRECT_UI_PASSED=1" "$marker" \
    || {
      echo "iOS physical Direct XCTest did not emit its exact UI receipt" >&2
      return 1
    }
  echo "iOS shipped Direct selection passed: $log"
}

run_vpn_cycle() {
  local device="$1"
  local args=(
    --nvpn-debug-exit-probe
    --nvpn-debug-wait-seconds "$VPN_START_WAIT_SECS"
    --nvpn-debug-result "$VPN_RESULT_NAME"
    --nvpn-debug-tun-probe-target "$TUN_PACKET_PROBE_TARGET"
    --nvpn-debug-tun-probe-port "$TUN_PACKET_PROBE_PORT"
    --nvpn-debug-tun-probe-count "$TUN_PACKET_PROBE_COUNT"
    --nvpn-debug-tun-probe-wait-seconds "$TUN_PACKET_PROBE_WAIT_SECS"
  )
  local wireguard_config=""
  if [[ -n "$DEBUG_WIREGUARD_CONFIG_FILE" ]]; then
    wireguard_config="$(<"$DEBUG_WIREGUARD_CONFIG_FILE")"
  elif [[ -n "$DEBUG_WIREGUARD_CONFIG" ]]; then
    wireguard_config="$DEBUG_WIREGUARD_CONFIG"
  fi
  if [[ -n "$wireguard_config" ]]; then
    args+=(--nvpn-debug-wireguard-config-base64 "$(printf '%s' "$wireguard_config" | base64 | tr -d '\n')")
  fi
  if [[ -n "$EXIT_DNS_MODE" ]] && ! bool_is_true "$EXIT_DNS_USE_SHIPPED_UI"; then
    args+=(
      --nvpn-debug-exit-dns-mode "$EXIT_DNS_MODE"
      --nvpn-debug-exit-dns-doh-provider "$EXIT_DNS_DOH_PROVIDER"
      --nvpn-debug-exit-dns-custom-doh-url "$EXIT_DNS_CUSTOM_DOH_URL"
      --nvpn-debug-exit-dns-custom-doh-bootstrap-ips "$EXIT_DNS_CUSTOM_DOH_BOOTSTRAP_IPS"
      --nvpn-debug-exit-dns-through-exit-servers "$EXIT_DNS_THROUGH_EXIT_SERVERS"
    )
  fi
  if [[ -n "$EXIT_PROBE_HOST" ]]; then
    args+=(--nvpn-debug-resolve-host "$EXIT_PROBE_HOST")
  fi
  if [[ -n "$EXIT_PROBE_URL" ]]; then
    args+=(--nvpn-debug-fetch-url "$EXIT_PROBE_URL")
  else
    args+=(--nvpn-debug-skip-fetch)
  fi
  if bool_is_true "$VERIFY_DIRECT_RESTORATION" \
    || bool_is_true "$SWITCH_TO_DIRECT_WHILE_CONNECTED"
  then
    args+=(
      --nvpn-debug-direct-resolve-host "$DIRECT_PROBE_HOST"
      --nvpn-debug-direct-fetch-url "$DIRECT_PROBE_URL"
    )
  fi
  if bool_is_true "$VERIFY_DIRECT_RESTORATION"; then
    args+=(--nvpn-debug-verify-direct-restoration)
  fi
  if bool_is_true "$SWITCH_TO_DIRECT_WHILE_CONNECTED"; then
    args+=(--nvpn-debug-await-direct-ui-while-connected)
  fi
  if bool_is_true "$CREATE_NETWORK"; then
    args+=(--nvpn-debug-add-network "$DEBUG_NETWORK_NAME")
  fi
  if bool_is_true "$cleanup_after_vpn_cycle"; then
    vpn_cleanup_armed=1
    vpn_cleanup_device="$device"
  fi
  if bool_is_true "$IOS_LIFECYCLE_GATE"; then
    run_ios_active_tunnel_lifecycle_gate \
      "$device" "$BUNDLE_ID" "$VPN_RESULT_DIR" \
      "$IOS_ACTIVE_TUNNEL_LIFECYCLE_CYCLES" "${args[@]}"
  elif bool_is_true "$SWITCH_TO_DIRECT_WHILE_CONNECTED"; then
    run_ios_connected_direct_ui_driver "$device" "${args[@]}"
  else
    launch_device "$device" "${args[@]}"
    sleep "$VPN_START_WAIT_SECS"
  fi
  local result_path
  if ! result_path="$(wait_for_vpn_probe_result "$device")"; then
    copy_ios_debug_logs "$device" || true
    return 1
  fi
  if ! validate_vpn_probe_result "$result_path"; then
    copy_ios_debug_logs "$device" || true
    return 1
  fi
  echo "iOS device VPN probe passed: $result_path"
  if ! bool_is_true "$VERIFY_DIRECT_RESTORATION"; then
    run_ios_device_idle_cpu_gate "$device" '^Nostr VPN Tunnel$' "iOS packet tunnel"
  fi
  cleanup_ios_vpn "$device"
}

cleanup_ios_vpn() {
  local device="$1"
  bool_is_true "$cleanup_after_vpn_cycle" || return 0
  if ! disconnect_ios_vpn_confirmed "$device"; then
    return 1
  fi
  vpn_cleanup_armed=0
  vpn_cleanup_device=""
}

cleanup_ios_vpn_on_exit() {
  local status="$?"
  trap - EXIT
  if [[ "$vpn_cleanup_armed" -eq 1 && -n "$vpn_cleanup_device" ]]; then
    if ! cleanup_ios_vpn "$vpn_cleanup_device"; then
      echo "iOS VPN emergency cleanup failed; turn the VPN off in iOS Settings before replacing the app." >&2
      if [[ "$status" -eq 0 ]]; then
        status=1
      fi
    fi
  fi
  exit "$status"
}

trap cleanup_ios_vpn_on_exit EXIT

run_device() {
  local device="${NVPN_IOS_DEVICE:-${NVPN_IOS_DEVICE_ID:-}}"
  if [[ -z "$device" ]]; then
    if device="$(select_physical_ios_device)"; then
      echo "iOS device smoke auto-selected the only connected physical mobile device"
    else
      exit 1
    fi
  fi

  xcrun devicectl device info details --device "$device" >/dev/null
  if [[ "$disconnect_only" -eq 1 ]]; then
    disconnect_ios_vpn_confirmed "$device"
    return
  fi
  if bool_is_true "$INSTALL_DEVICE_APP"; then
    install_device_app "$device"
  fi
  if bool_is_true "$IOS_LIFECYCLE_GATE" && [[ "$vpn_cycle" -eq 0 ]]; then
    disconnect_ios_vpn_confirmed "$device"
    run_ios_app_lifecycle_gate \
      "$device" "$BUNDLE_ID" "$VPN_RESULT_DIR" "$IOS_LIFECYCLE_CYCLES"
  fi
  if [[ "$vpn_cycle" -eq 1 ]]; then
    run_vpn_cycle "$device"
  else
    disconnect_ios_vpn_confirmed "$device"
    run_ios_device_idle_cpu_gate "$device" '^Nostr VPN$' "iOS foreground app"
  fi
  echo "iOS device smoke launched bundle $BUNDLE_ID"
}

case "$mode" in
  simulator|sim)
    run_simulator
    ;;
  device)
    run_device
    ;;
  -h|--help|help)
    usage
    ;;
  *)
    usage
    exit 2
    ;;
esac
