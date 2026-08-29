#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
release_gate="$ROOT/scripts/lib-mobile-android-release-gate.sh"
android_smoke="$ROOT/scripts/mobile-android-smoke.sh"

python3 - "$release_gate" "$android_smoke" <<'PY'
import pathlib
import re
import sys

release_gate = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
android_smoke = pathlib.Path(sys.argv[2]).read_text(encoding="utf-8")

if re.search(r'mktemp "[^"]*XXXXXX\.[^"]+"', release_gate):
    raise SystemExit("Android release gate uses a non-portable mktemp suffix")


def function_body(source: str, name: str, next_name: str) -> str:
    start_marker = f"{name}() {{"
    end_marker = f"{next_name}() {{"
    try:
        start = source.index(start_marker)
        end = source.index(end_marker, start + len(start_marker))
    except ValueError as error:
        raise SystemExit(f"missing cleanup contract function: {error}")
    return source[start:end]


arm = "vpn_cleanup_armed=1"
stable = "android_release_wait_stable_quiescence"
disarm = "vpn_cleanup_armed=0"
for obsolete in (
    "android_release_rapid_cancel_once",
    "android_release_sleep_milliseconds",
    "for delay_ms in 0 10 30 80 160 320 640 1000",
    "shell input tap $point",
):
    if obsolete in release_gate:
        raise SystemExit(f"Release start/stop gate retains synthetic timing: {obsolete!r}")

disconnect = function_body(
    release_gate,
    "android_release_disconnect_ui",
    "android_release_emergency_cleanup",
)
if "if ! vpn_state_present" in disconnect:
    raise SystemExit(
        "Release disconnect still skips the shipped toggle when OS VPN state is absent"
    )
for receipt in (
    "android_release_vpn_toggle_checked",
    "android_release_vpn_off_and_inactive",
    'echo "Android Release VPN-off gesture produced no UI state change; retrying once"',
):
    if receipt not in disconnect:
        raise SystemExit(f"Release disconnect is missing {receipt!r}")
if disconnect.count('tap_android_ui description "Turn VPN off"') != 2:
    raise SystemExit("Release disconnect must allow exactly one bounded shipped-UI retap")
if disconnect.count('wait_until "$VPN_STOP_WAIT_SECS" android_release_vpn_off_and_inactive') != 2:
    raise SystemExit("Release disconnect must prove OS/UI shutdown after each bounded gesture")
if disconnect.index("retrying once") > disconnect.rindex(
    'tap_android_ui description "Turn VPN off"'
):
    raise SystemExit("Release disconnect retry is not announced before its second gesture")

quiescence = function_body(
    release_gate,
    "android_release_wait_stable_quiescence",
    "android_release_connect_ui",
)
for receipt in (
    "vpn_inactive",
    'checked" == "false"',
    "android_vpn_native_start_count",
    "stable_since_ms",
    "stable_ms=1000",
    "expected_count",
):
    if receipt not in quiescence:
        raise SystemExit(f"stable-quiescence proof is missing {receipt!r}")

toggle_now = function_body(
    release_gate,
    "android_release_vpn_toggle_checked_now",
    "android_release_vpn_off_and_inactive",
)
if toggle_now.count("android_ui_vpn_toggle_checked") != 1:
    raise SystemExit("Release toggle polling does not use one shared UI snapshot")
if "android_ui_query" in toggle_now:
    raise SystemExit("Release toggle polling still performs duplicate UI dumps")

toggle_snapshot = function_body(
    android_smoke,
    "android_ui_vpn_toggle_checked",
    "android_ui_query",
)
for receipt in (
    "uiautomator dump",
    '"Turn VPN off"',
    '"Turn VPN on"',
):
    if receipt not in toggle_snapshot:
        raise SystemExit(f"single-snapshot toggle parser is missing {receipt!r}")
if toggle_snapshot.count("uiautomator dump") != 1:
    raise SystemExit("single-snapshot toggle parser performs multiple UI dumps")

rapid_gate = function_body(
    release_gate,
    "run_android_release_rapid_start_stop_gate",
    "run_android_release_blackbox_cycle",
)
if rapid_gate.count("android_release_capture_native_tunnel_start_baseline") != 1:
    raise SystemExit(
        "Release reconnect gate must reset native-start evidence once"
    )
for receipt, expected in (
    (arm, 1),
    ("android_release_connect_ui", 1),
    ("run_android_release_exit_network_probe", 1),
    ("android_release_disconnect_ui", 1),
    (stable, 1),
    (disarm, 1),
    ("run_android_release_exit_network_probe start-stop-initial-exit", 0),
    ("run_android_release_exit_network_probe start-stop-full-reconnect", 1),
):
    if rapid_gate.count(receipt) != expected:
        raise SystemExit(
            f"Release semantic start/stop gate has {rapid_gate.count(receipt)} "
            f"instances of {receipt!r}, expected {expected}"
        )
positions = [
    rapid_gate.index(receipt)
    for receipt in (
        arm, "android_release_connect_ui", "run_android_release_exit_network_probe",
        "android_release_disconnect_ui", stable, disarm,
    )
]
if positions != sorted(positions):
    raise SystemExit("Release reconnect cleanup is not armed through stable quiescence")
for receipt in (
    'expected_pid="$(android_app_pid)"',
    '[[ "$(android_app_pid)" == "$expected_pid" ]]',
    "printf 'semantic\\t%s\\t%s\\n'",
    '>>"$start_stop_ledger"',
):
    if rapid_gate.count(receipt) != 1:
        raise SystemExit(
            f"Release semantic start/stop gate must emit one exact receipt: {receipt!r}"
        )
if rapid_gate.index('>>"$start_stop_ledger"') < rapid_gate.index(disarm):
    raise SystemExit("Release start/stop receipt is emitted before stable cleanup")

emergency = function_body(
    release_gate,
    "android_release_emergency_cleanup",
    "run_android_release_direct_https_probe",
)
initial_ui_cleanup = emergency.index("if android_release_disconnect_ui")
force_stop = emergency.index('shell am force-stop "$PACKAGE_NAME"')
fallback_ui_cleanup = emergency.index(
    "android_release_disconnect_ui", force_stop + 1
)
if not initial_ui_cleanup < force_stop < fallback_ui_cleanup:
    raise SystemExit(
        "Release emergency cleanup does not reserve force-stop for failed UI cleanup"
    )
for receipt in (
    "android_release_wait_stable_quiescence",
    "emergency-cleanup-after-force-stop",
):
    if receipt not in emergency:
        raise SystemExit(f"Release emergency cleanup is missing {receipt!r}")

cleanup = function_body(
    android_smoke,
    "cleanup_android_vpn_on_exit",
    "android_sdk",
)
for receipt in (
    '[[ "$vpn_cleanup_armed" -eq 1 ]]',
    "android_release_emergency_cleanup",
    "OS VPN inactive, shipped toggle Off, native start count stable",
):
    if receipt not in cleanup:
        raise SystemExit(f"Release emergency cleanup is missing {receipt!r}")

print("Android Release semantic start/stop cleanup source contract passed")
PY
