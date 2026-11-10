#!/usr/bin/env python3
"""Check durable Android UI evidence without a device or UI replay."""
import os
from pathlib import Path
import re
import signal
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parent.parent
LIBRARY = ROOT / 'scripts/lib-mobile-release-join-ui.sh'

with tempfile.TemporaryDirectory(prefix='nvpn-ui-evidence-') as temporary:
    directory = Path(temporary)
    environment = dict(os.environ, LIBRARY=str(LIBRARY), ROOT=str(ROOT),
                       PRIVATE_DIR=str(directory), EVIDENCE=str(directory / 'retained.xml'))
    capture = '''set -euo pipefail
source "$LIBRARY"
[[ "$SELECTED" == 0 ]] || RELEASE_JOIN_ANDROID_UI_XML="$EVIDENCE"
ADB=(fixture_adb)
fixture_adb() {
  if [[ "$1" == shell ]]; then return "$DUMP_STATUS"; fi
  if [[ "$READ_STATUS" != 0 ]]; then printf '<partial'; return "$READ_STATUS"; fi
  printf '<hierarchy><node resource-id="accepted" bounds="[0,0][100,100]"/></hierarchy>'
}
DUMP_STATUS=0 READ_STATUS=0
release_join_android_query resource accepted center
before="$(cat "$RELEASE_JOIN_ANDROID_UI_XML")"
DUMP_STATUS=7
if release_join_android_query resource accepted center; then exit 91; fi
[[ "$(cat "$RELEASE_JOIN_ANDROID_UI_XML")" == "$before" ]]
DUMP_STATUS=0 READ_STATUS=9
if release_join_android_query resource accepted center; then exit 92; fi
[[ "$(cat "$RELEASE_JOIN_ANDROID_UI_XML")" == "$before" ]]
[[ "$(cat "$RELEASE_JOIN_ANDROID_UI_XML.tmp")" == '<partial' ]]
printf '%s\n' "$RELEASE_JOIN_ANDROID_UI_XML"
'''
    for selected in ('0', '1'):
        result = subprocess.run(['bash', '-c', capture], env=dict(environment, SELECTED=selected),
                                text=True, capture_output=True, timeout=5)
        assert result.returncode == 0, (result.returncode, result.stderr)
        expected = directory / ('retained.xml' if selected == '1' else 'android-ui.xml')
        assert result.stdout.splitlines() == ['50 50', str(expected)]
    print('PASS: default and selected evidence paths; fresh queries succeed; failed dump/read reject stale evidence and retain the last completed XML')

    # Interrupt an actual local shell group during the stubbed device read.
    # The selected snapshot must survive even when no cleanup trap executes.
    previous = (directory / 'retained.xml').read_bytes()
    blocked = directory / 'blocked'
    script = '''set -euo pipefail
source "$LIBRARY"
RELEASE_JOIN_ANDROID_UI_XML="$EVIDENCE"
ADB=(fixture_adb)
fixture_adb() {
  [[ "$1" != shell ]] || return 0
  printf '<interrupted'
  : >"$BLOCKED"
  while :; do sleep 1; done
}
release_join_android_dump_ui
'''
    child = subprocess.Popen(['bash', '-c', script], env=dict(environment, BLOCKED=str(blocked)),
                             start_new_session=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        end = time.monotonic() + 3
        while not blocked.exists() and time.monotonic() < end:
            assert child.poll() is None
            time.sleep(.01)
        assert blocked.exists()
        os.killpg(child.pid, signal.SIGTERM)
        child.communicate(timeout=3)
        assert child.returncode == -signal.SIGTERM
        assert (directory / 'retained.xml').read_bytes() == previous
        assert (directory / 'retained.xml.tmp').read_text() == '<interrupted'
    finally:
        if child.poll() is None:
            os.killpg(child.pid, signal.SIGKILL)
            child.communicate(timeout=3)
        end = time.monotonic() + 3
        while time.monotonic() < end:
            try:
                os.killpg(child.pid, 0)
            except ProcessLookupError:
                break
            time.sleep(.01)
        else:
            raise AssertionError('fixture process group remains')
    print('PASS: interrupted read preserves completed XML and separate partial file; exact local fixture group closed')

    setup = '''set -euo pipefail
source "$LIBRARY"
RELEASE_JOIN_UI_WAIT_SECS=2
release_join_require_device_mutation_allowed() { [[ "$CASE" != denied ]]; }
release_join_android_stop() { :; }
release_join_android_launch() { :; }
release_join_android_dump_ui() { :; }
release_join_android_query_dumped() {
  if [[ "$1" == description ]]; then [[ "$CASE" == fresh ]]; else return 0; fi
}
release_join_android_normalize_carrier() { :; }
release_join_android_tap_center() { :; }
release_join_android_tap_visible() { :; }
release_join_android_query() { return 0; }
release_join_android_scroll_to() { [[ "$CASE:$2" != 'scroll-failed:Add network' ]]; }
release_join_android_wait_query() { [[ "$CASE" != wait-failed ]] || return 7; }
release_join_android_open_network_setup
'''
    steps = ['start', 'launched', 'carrier-settings', 'internet-source', 'network-picker', 'add-network']
    for case, expected_status, expected_steps in [
        ('denied', 1, []), ('fresh', 0, ['start', 'launched', 'ready']),
        ('saved', 0, steps + ['ready']), ('scroll-failed', 1, steps),
        ('wait-failed', 7, steps),
    ]:
        result = subprocess.run(['bash', '-c', setup], env=dict(environment, CASE=case),
                                text=True, capture_output=True, timeout=3)
        assert result.returncode == expected_status, (case, result.returncode, result.stderr)
        rows = [re.fullmatch(r'NVPN_ANDROID_SETUP step=([a-z-]+) elapsed=(\d+)', line)
                for line in result.stderr.splitlines()]
        assert all(rows) and [row[1] for row in rows] == expected_steps, (case, result.stderr)
        elapsed = [int(row[2]) for row in rows]
        assert elapsed == sorted(elapsed) and not result.stdout
    print('PASS: five setup branches retain status, ordered elapsed markers and no false ready marker; device operations stubbed')

source = (ROOT / 'scripts/macos-vm-release-mobile-join-e2e.sh').read_text()
for label in ('macos-admin-pixel-joiner', 'pixel-admin-macos-joiner'):
    section = source.split('MACOS_MOBILE_DIRECTION_LABEL=' + label + '\n', 1)[1]
    assert section.startswith('RELEASE_JOIN_ANDROID_UI_XML="$RESULT_DIR/macos/$MACOS_MOBILE_DIRECTION_LABEL-android-ui.xml"\n')
    assert 'release_join_android_open_network_setup \\\n  2>"$RESULT_DIR/macos/$MACOS_MOBILE_DIRECTION_LABEL-android-setup.log"\n' in section
print('PASS: both Mac/Pixel directions retain separate XML and setup logs before later cleanup; no VM/device used')
