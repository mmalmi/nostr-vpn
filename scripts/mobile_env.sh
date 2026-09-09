#!/usr/bin/env bash

load_mobile_env() {
  local root="$1"
  local env_file="${NVPN_MOBILE_ENV_FILE:-$root/.env.mobile.local}"

  declare -F load_env_file_defaults >/dev/null || {
    echo "load_mobile_env requires release_common.sh" >&2
    return 1
  }
  load_env_file_defaults "$env_file"
}

select_physical_android_serial() {
  local adb="$1"
  local requested="${2:-}"
  local selected=""

  if [[ -n "$requested" ]]; then
    if [[ "$requested" == emulator-* ]]; then
      printf 'Physical Android test refuses emulator serial %s\n' "$requested" >&2
      return 1
    fi
    if ! "$adb" devices 2>/dev/null | awk -v requested="$requested" '
      NR > 1 && $1 == requested && $2 == "device" { found = 1 }
      END { exit !found }
    '; then
      printf 'Requested physical Android device is not online: %s\n' "$requested" >&2
      return 1
    fi
    printf '%s\n' "$requested"
    return
  fi

  selected="$("$adb" devices 2>/dev/null | awk '
    NR > 1 && $2 == "device" && $1 !~ /^emulator-/ {
      print $1
      exit
    }
  ')"
  if [[ -z "$selected" ]]; then
    printf 'No physical Android device is online; emulators do not satisfy this test\n' >&2
    return 1
  fi
  printf '%s\n' "$selected"
}

select_physical_ios_device_with_devicectl() {
  local devices_file candidates_file ready_file candidate wired
  local count wired_count selected
  devices_file="$(mktemp "${TMPDIR:-/tmp}/nvpn-ios-devices.XXXXXX")"
  candidates_file="$(mktemp "${TMPDIR:-/tmp}/nvpn-ios-candidates.XXXXXX")"
  ready_file="$(mktemp "${TMPDIR:-/tmp}/nvpn-ios-ready.XXXXXX")"

  if ! xcrun devicectl list devices \
    --json-output "$devices_file" >/dev/null 2>&1
  then
    rm -f "$devices_file" "$candidates_file" "$ready_file"
    return 1
  fi

  if ! python3 - "$devices_file" >"$candidates_file" <<'PY'
import json
import re
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    payload = json.load(handle)

devices = payload.get("result", {}).get("devices", [])
candidates = {}
for device in devices:
    hardware = device.get("hardwareProperties", {})
    platform = str(hardware.get("platform", "")).lower()
    if platform not in {"ios", "ipados"}:
        continue
    udid = hardware.get("udid")
    if not isinstance(udid, str) or not re.fullmatch(r"[0-9A-Fa-f-]{8,}", udid):
        continue
    connection = device.get("connectionProperties", {})
    wired = str(connection.get("transportType", "")).lower() == "wired"
    candidates[udid] = candidates.get(udid, False) or wired

for udid, wired in sorted(candidates.items()):
    print(f"{int(wired)}\t{udid}")
PY
  then
    rm -f "$devices_file" "$candidates_file" "$ready_file"
    return 1
  fi

  while IFS="$(printf '\t')" read -r wired candidate; do
    [[ -n "$candidate" ]] || continue
    if xcrun devicectl device info details \
      --device "$candidate" >/dev/null 2>&1
    then
      printf '%s\t%s\n' "$wired" "$candidate" >>"$ready_file"
    fi
  done <"$candidates_file"
  rm -f "$devices_file" "$candidates_file"

  count="$(awk 'NF { count++ } END { print count + 0 }' "$ready_file")"
  if [[ "$count" == "1" ]]; then
    selected="$(awk 'NF { print $2; exit }' "$ready_file")"
    rm -f "$ready_file"
    printf '%s\n' "$selected"
    return 0
  fi

  if (( count > 1 )); then
    wired_count="$(awk '$1 == 1 { count++ } END { print count + 0 }' "$ready_file")"
    if [[ "$wired_count" == "1" ]]; then
      selected="$(awk '$1 == 1 { print $2; exit }' "$ready_file")"
      rm -f "$ready_file"
      printf '%s\n' "$selected"
      return 0
    fi
    rm -f "$ready_file"
    printf 'Multiple physical iOS devices are online; set NVPN_IOS_DEVICE\n' >&2
    return 2
  fi

  rm -f "$ready_file"
  return 1
}

select_physical_ios_device() {
  local requested="${1:-${NVPN_IOS_DEVICE:-${NVPN_IOS_DEVICE_ID:-}}}"
  local selected=""
  local status=0

  if [[ -n "$requested" ]]; then
    if ! xcrun devicectl device info details --device "$requested" >/dev/null 2>&1; then
      printf 'Requested physical iOS device is not online\n' >&2
      return 1
    fi
    printf '%s\n' "$requested"
    return
  fi

  selected="$(select_physical_ios_device_with_devicectl)" || status=$?
  case "$status" in
    0)
      printf '%s\n' "$selected"
      return
      ;;
    2)
      return 1
      ;;
  esac

  status=0
  selected="$(xcrun xctrace list devices 2>/dev/null | awk '
    /^== Devices ==/ { in_devices = 1; next }
    /^== Devices Offline ==/ || /^== Simulators ==/ { in_devices = 0 }
    in_devices && /iPhone|iPad/ {
      device = $0
      sub(/^.*\(/, "", device)
      sub(/\)[[:space:]]*$/, "", device)
      if (device ~ /^[0-9A-Fa-f-]{8,}$/) devices[++count] = device
    }
    END {
      if (count == 1) { print devices[1]; exit 0 }
      if (count > 1) exit 2
      exit 1
    }
  ')" || status=$?
  case "$status" in
    0)
      printf '%s\n' "$selected"
      ;;
    2)
      printf 'Multiple physical iOS devices are online; set NVPN_IOS_DEVICE\n' >&2
      return 1
      ;;
    *)
      printf 'No physical iOS device is online\n' >&2
      return 1
      ;;
  esac
}

resolve_physical_ios_udid() {
  local device="$1"
  local details_file udid
  details_file="$(mktemp "${TMPDIR:-/tmp}/nvpn-ios-device-details.XXXXXX")"
  if ! xcrun devicectl device info details \
    --device "$device" \
    --json-output "$details_file" \
    --quiet >/dev/null
  then
    rm -f "$details_file"
    printf 'Could not inspect the selected physical iOS device\n' >&2
    return 1
  fi
  udid="$(python3 - "$details_file" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    details = json.load(handle)
value = details.get("result", {}).get("hardwareProperties", {}).get("udid")
if not isinstance(value, str) or not value.strip():
    raise SystemExit(1)
print(value.strip())
PY
  )" || {
    rm -f "$details_file"
    printf 'The selected physical iOS device did not report a hardware UDID\n' >&2
    return 1
  }
  rm -f "$details_file"
  printf '%s\n' "$udid"
}

ios_device_launch() {
  local device="$1"
  local bundle_id="$2"
  shift 2

  if [[ "$#" -eq 0 ]]; then
    xcrun devicectl device process launch \
      --device "$device" \
      --activate \
      "$bundle_id"
    return
  fi

  local encoded_arguments
  encoded_arguments="$(python3 - "$@" <<'PY'
import base64
import json
import sys

payload = json.dumps(sys.argv[1:], separators=(",", ":")).encode()
print(base64.urlsafe_b64encode(payload).decode().rstrip("="))
PY
)"
  xcrun devicectl device process launch \
    --device "$device" \
    --activate \
    --payload-url "nvpn://debug/automation?arguments=$encoded_arguments" \
    "$bundle_id"
}
