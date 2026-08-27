#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT_DIR/scripts/mobile_env.sh"

fail() {
  printf 'mobile physical-device selection harness failed: %s\n' "$*" >&2
  exit 1
}

tmp="$(mktemp -d "${TMPDIR:-/tmp}/nvpn-mobile-device-selection.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT

cat >"$tmp/adb" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ "${1:-}" == "devices" ]] || exit 2
printf 'List of devices attached\n'
printf 'emulator-5554\tdevice\n'
printf 'physical-device\tdevice\n'
printf 'offline-device\toffline\n'
EOF
chmod +x "$tmp/adb"

selected="$(select_physical_android_serial "$tmp/adb" "")"
[[ "$selected" == "physical-device" ]] \
  || fail "automatic selection chose '$selected' instead of the physical device"

selected="$(select_physical_android_serial "$tmp/adb" "physical-device")"
[[ "$selected" == "physical-device" ]] \
  || fail "explicit physical selection returned '$selected'"

if select_physical_android_serial "$tmp/adb" "emulator-5554" >/dev/null 2>&1; then
  fail "physical-only selection accepted an emulator"
fi

cat >"$tmp/adb" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ "${1:-}" == "devices" ]] || exit 2
printf 'List of devices attached\n'
printf 'emulator-5554\tdevice\n'
EOF
chmod +x "$tmp/adb"

if select_physical_android_serial "$tmp/adb" "" >/dev/null 2>&1; then
  fail "physical-only selection fell back to an emulator"
fi

cat >"$tmp/xcrun" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

if [[ "${1:-}" == "devicectl" && "${2:-}" == "list" && "${3:-}" == "devices" ]]; then
  output=""
  shift 3
  while (( $# > 0 )); do
    case "$1" in
      --json-output)
        output="$2"
        shift 2
        ;;
      *)
        shift
        ;;
    esac
  done
  cp "$NVPN_FAKE_DEVICE_LIST" "$output"
  exit 0
fi

if [[ "${1:-}" == "devicectl" && "${2:-}" == "device" \
  && "${3:-}" == "info" && "${4:-}" == "details" ]]; then
  exit 0
fi

if [[ "${1:-}" == "xctrace" && "${2:-}" == "list" \
  && "${3:-}" == "devices" ]]; then
  printf '== Devices ==\n'
  printf '== Devices Offline ==\n'
  printf 'Connected iPhone (17.0) (00000000-0000000000000000)\n'
  printf '== Simulators ==\n'
  exit 0
fi

exit 2
EOF
chmod +x "$tmp/xcrun"

cat >"$tmp/devices.json" <<'EOF'
{
  "result": {
    "devices": [
      {
        "hardwareProperties": {
          "platform": "iOS",
          "udid": "00000000-0000000000000001"
        },
        "connectionProperties": {
          "transportType": "wired"
        }
      }
    ]
  }
}
EOF

selected="$(
  PATH="$tmp:$PATH" \
    NVPN_FAKE_DEVICE_LIST="$tmp/devices.json" \
    select_physical_ios_device ""
)"
[[ "$selected" == "00000000-0000000000000001" ]] \
  || fail "iOS selection ignored the connected devicectl device"

cat >"$tmp/devices.json" <<'EOF'
{
  "result": {
    "devices": [
      {
        "hardwareProperties": {
          "platform": "iOS",
          "udid": "00000000-0000000000000001"
        },
        "connectionProperties": {
          "transportType": "localNetwork"
        }
      },
      {
        "hardwareProperties": {
          "platform": "iOS",
          "udid": "00000000-0000000000000001"
        },
        "connectionProperties": {
          "transportType": "wired"
        }
      }
    ]
  }
}
EOF

selected="$(
  PATH="$tmp:$PATH" \
    NVPN_FAKE_DEVICE_LIST="$tmp/devices.json" \
    select_physical_ios_device ""
)"
[[ "$selected" == "00000000-0000000000000001" ]] \
  || fail "iOS selection did not deduplicate one device across transports"

cat >"$tmp/devices.json" <<'EOF'
{
  "result": {
    "devices": [
      {
        "hardwareProperties": {
          "platform": "iOS",
          "udid": "00000000-0000000000000001"
        },
        "connectionProperties": {
          "transportType": "localNetwork"
        }
      },
      {
        "hardwareProperties": {
          "platform": "iOS",
          "udid": "00000000-0000000000000002"
        },
        "connectionProperties": {
          "transportType": "wired"
        }
      }
    ]
  }
}
EOF

selected="$(
  PATH="$tmp:$PATH" \
    NVPN_FAKE_DEVICE_LIST="$tmp/devices.json" \
    select_physical_ios_device ""
)"
[[ "$selected" == "00000000-0000000000000002" ]] \
  || fail "iOS selection did not prefer the single wired physical device"

printf 'mobile physical-device selection harness passed\n'
