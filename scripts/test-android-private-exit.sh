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
picker() { release_join_android_tap_visible resource internet-source-picker; }
select_source() {
  picker && release_join_android_wait_query resource "internet-source-$1" 10 &&
    release_join_android_tap_center resource "internet-source-$1"
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
echo 'Android opened the Internet source picker flow'
select_source private_vpn || { echo 'Could not select the private VPN source' >&2; exit 1; }
release_join_android_wait_query text "$provider" 90 || { echo "The paired provider was absent from the private VPN picker" >&2; exit 1; }
provider_mark() {
  release_join_android_dump_ui && python3 - "$RELEASE_JOIN_ANDROID_UI_XML" "$provider" "$1" <<'PYROW'
import sys
import xml.etree.ElementTree as ET
path, peer, mark = sys.argv[1:]
root = ET.parse(path).getroot()
rows = [row for row in root.iter("node") if row.get("clickable") == "true"
        and any(child.get("text") == peer for child in row.iter("node"))]
assert len(rows) == 1
assert any(child.get("text") == mark for child in rows[0].iter("node"))
PYROW
}
provider_mark '○'
"${ADB[@]}" exec-out screencap -p >"$out/before-selection.png"
echo 'NVPN_ANDROID_PRIVATE_EXIT_VISIBLE=1'
release_join_android_tap_visible text "$provider"
deadline=$((SECONDS + 50))
until probe available 2>/dev/null; do
  ((SECONDS < deadline)) || { echo 'Private exit did not deliver its fresh challenge' >&2; exit 1; }
  sleep 0.5
done
release_join_android_os_vpn_connected
provider_mark '●'
echo 'NVPN_ANDROID_PRIVATE_EXIT_TRAFFIC_VERIFIED=1'
