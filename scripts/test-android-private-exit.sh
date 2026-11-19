#!/usr/bin/env bash
# Drive the installed Android app using a peer already admitted to its test network.
set -euo pipefail
trap 'echo "Android private exit verifier stopped at line $LINENO" >&2' ERR
umask 077
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/scripts/lib-mobile-release-join-ui.sh"
provider="${1:?supply the paired provider npub}"
challenge="${2:?supply the fresh fixture challenge}"
host="${3:?supply the fixture IP}"
port="${4:?supply the fixture port}"
out="${5:?supply a fresh evidence directory}"
release_join_valid_npub "$provider"
[[ "$challenge" =~ ^[0-9a-f]{32}$ && "$port" =~ ^[1-9][0-9]{0,4}$ && "$port" -le 65535 ]]
python3 -c 'import ipaddress, sys; assert ipaddress.ip_address(sys.argv[1]) in ipaddress.ip_network("198.18.0.0/15")' "$host"
ADB=("${ADB_BIN:-adb}" -s "${NVPN_ANDROID_SERIAL:?select the physical phone}")
[[ ! -e "$out" ]]
mkdir -p "$out"
PRIVATE_DIR="$out/private"
mkdir "$PRIVATE_DIR"
RELEASE_JOIN_UI_WAIT_SECS=25
"${ADB[@]}" shell dumpsys window policy | grep -E '^[[:space:]]*showing=false[[:space:]]*$' >/dev/null
"${ADB[@]}" shell toybox nc --help >"$out/nc-help.log" 2>&1
grep -Eq 'netcat|nc ' "$out/nc-help.log"
"${ADB[@]}" shell am start -W -n fi.siriusbusiness.nvpn/org.nostrvpn.app.MainActivity >/dev/null
# Waiting for an explicitly paired fixture to be usable is independent of the
# release join-delivery timing check. No join timing is recorded here.
# Devices and Internet are fixed bottom tabs. The scrolling-content viewport
# intentionally excludes them, including when the current account is a joiner.
release_join_android_wait_query description 'Devices tab'
release_join_android_tap_center description 'Devices tab'
release_join_android_wait_query resource "roster-participant-accepted-$provider" 80
echo 'Android confirmed the paired provider in the roster'
release_join_android_wait_query description 'Internet tab'
release_join_android_tap_center description 'Internet tab'
release_join_android_scroll_to resource internet-source-picker safe-center backward
select_source() {
  local label
  case "$1" in
    private_vpn) label='Internet source Private VPN device' ;;
    direct) label='Internet source This device' ;;
    *) return 2 ;;
  esac
  # Android exposes the menu items' accessibility labels in the separate
  # popup window, even when Compose omits their resource IDs there.
  if ! release_join_android_query description "$label" center >/dev/null 2>&1; then
    release_join_android_scroll_to resource internet-source-picker safe-center backward || return 1
    release_join_android_tap_visible resource internet-source-picker || return 1
  fi
  release_join_android_wait_query description "$label" 10 &&
    release_join_android_tap_center description "$label"
}
probe() {
  # The shell UID is outside the VPN app. Use the production OS routes and a
  # fresh GET, with a deadline on the complete response as well as connect.
  python3 - "${ADB[0]}" "${ADB[2]}" "$host" "$port" "$challenge" "$1" <<'PYPROBE'
import subprocess, sys
adb, serial, host, port, challenge, condition = sys.argv[1:]
request = f"GET /{challenge} HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode()
try:
    answer = subprocess.run([adb, "-s", serial, "shell", "-T", "toybox", "nc", "-w", "3", host, port],
                            input=request, capture_output=True, timeout=6)
except subprocess.TimeoutExpired:
    sys.exit(0 if condition == "unavailable" else 1)
headers, _, body = answer.stdout.partition(b"\r\n\r\n")
if condition == "unavailable":
    assert subprocess.check_output([adb, "-s", serial, "get-state"], timeout=4).strip() == b"device"
    assert not headers.startswith(b"HTTP/") and not body
    assert not any(word in answer.stderr.lower() for word in (b"offline", b"not found", b"unknown option"))
else:
    assert answer.returncode == 0 and b" 200 " in headers.splitlines()[0] and body.strip() == challenge.encode()
PYPROBE
}
release_join_android_wait_query text 'This device' 15
was_on=0
if release_join_android_os_vpn_connected; then was_on=1; fi
restore_vpn=0
restore_source=0
restore() {
  local rc=$?
  trap - EXIT INT TERM HUP
  set +e
  if ((restore_source)); then
    if select_source direct && release_join_android_wait_query text 'This device' 20 && probe unavailable; then
      echo 'NVPN_ANDROID_PRIVATE_EXIT_DIRECT_RESTORED=1'
    else rc=1; fi
  fi
  if ((restore_vpn)); then
    if release_join_android_query description 'Turn VPN off' center >/dev/null; then
      release_join_android_tap_center description 'Turn VPN off' || rc=1
    fi
    release_join_android_wait_query description 'Turn VPN on' 15 || rc=1
    if release_join_android_os_vpn_connected; then rc=1; fi
  fi
  "${ADB[@]}" shell rm -f /sdcard/nvpn-release-join.xml >/dev/null || rc=1
  exit "$rc"
}
trap restore EXIT
trap 'exit 143' TERM HUP
trap 'exit 130' INT
probe unavailable
if (( ! was_on )); then
  release_join_android_wait_query description 'Turn VPN on'
  restore_vpn=1
  release_join_android_tap_center description 'Turn VPN on'
  release_join_android_wait_vpn_connected
fi
restore_source=1
echo 'Android verified the direct source before opening the picker'
select_source private_vpn || { echo 'Could not select the private VPN source' >&2; exit 1; }
provider_point_in_dump() {
  python3 - "$RELEASE_JOIN_ANDROID_UI_XML" "$provider" "$1" <<'PYROW' || return 1
import sys
import xml.etree.ElementTree as ET
path, peer, mark = sys.argv[1:]
rows = [row for row in ET.parse(path).getroot().iter("node")
        if row.get("clickable") == "true" and row.get("enabled") == "true"
        and any(child.get("text") == peer for child in row.iter("node"))]
sys.exit(0 if len(rows) == 1 and any(child.get("text") == mark for child in rows[0].iter("node")) else 1)
PYROW
  release_join_android_query_dumped clickable-row-text "$provider" visible-center
}
wait_provider_point() {
  local mark="$1" deadline=$((SECONDS + $2)) point
  while ((SECONDS < deadline)); do
    if release_join_android_dump_ui && point="$(provider_point_in_dump "$mark")"; then
      printf '%s\n' "$point"
      return 0
    fi
    sleep 0.25
  done
  echo "Paired provider row did not reach selection state $mark within ${2}s" >&2
  return 1
}
# Resolve the selection mark and tap bounds from the same accessibility tree.
# Discovery can redraw the list between two separate UIAutomator queries.
point="$(wait_provider_point '○' 90)"
cp "$PRIVATE_DIR/android-ui.xml" "$out/before-selection.xml"
"${ADB[@]}" exec-out screencap -p >"$out/before-selection.png"
echo 'NVPN_ANDROID_PRIVATE_EXIT_VISIBLE=1'
# shellcheck disable=SC2086
"${ADB[@]}" shell input tap $point
last_tap=$SECONDS
deadline=$((SECONDS + 45))
while true; do
  if release_join_android_dump_ui; then
    if provider_point_in_dump '●' >/dev/null; then
      cp "$PRIVATE_DIR/android-ui.xml" "$out/selected-provider.xml"
      echo 'Android confirmed the paired provider was selected'
      break
    fi
    # A discovery redraw can remove the button just before the tap arrives.
    # Retry only when this exact provider is visibly still unselected.
    if ((SECONDS - last_tap >= 5)) && point="$(provider_point_in_dump '○')"; then
      # shellcheck disable=SC2086
      "${ADB[@]}" shell input tap $point
      last_tap=$SECONDS
    fi
  fi
  ((SECONDS < deadline)) || { echo 'Android did not confirm the provider selection' >&2; exit 1; }
  sleep 0.25
done
deadline=$((SECONDS + 50))
until probe available 2>/dev/null; do
  ((SECONDS < deadline)) || { echo 'Private exit did not deliver its fresh challenge' >&2; exit 1; }
  sleep 0.5
done
release_join_android_os_vpn_connected
wait_provider_point '●' 25 >/dev/null
cp "$PRIVATE_DIR/android-ui.xml" "$out/after-traffic.xml"
echo 'NVPN_ANDROID_PRIVATE_EXIT_TRAFFIC_VERIFIED=1'
