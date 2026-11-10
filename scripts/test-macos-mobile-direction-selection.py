#!/usr/bin/env python3
"""Exercise the canonical role selectors and isolated-result boundary offline."""
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent
SOURCE = (ROOT / 'macos-vm-release-mobile-join-e2e.sh').read_text()

def run(script, selection, reused='', status=0, ios_status=0, expected=0, **environment):
    result = subprocess.run(['bash', '-euc', script], capture_output=True, text=True,
        env=dict(os.environ, MACOS_MOBILE_DIRECTIONS=selection,
                 REUSED_PIXEL_RECEIPT_SHA256=reused, android_admin_macos_status=str(status),
                 macos_admin_android_status='0', macos_admin_ios_status='0',
                 ios_admin_macos_status=str(ios_status), **environment), timeout=3)
    assert result.returncode == expected, (selection, status, result.returncode, result.stderr)
    return result.stdout.strip()

selection = re.search(r'^case "\$MACOS_MOBILE_DIRECTIONS" in\n.*?^esac\n', SOURCE, re.M | re.S)[0]
first = SOURCE.split('# macOS admin -> physical Android joiner.\n', 1)[1]
first = first[:first.index('set +e\n')]
reverse = SOURCE.split('# Physical Android admin -> macOS joiner.', 1)[1]
reverse = re.search(r'^if \[\[.*?; then\n', reverse, re.M | re.S)[0]
apple = re.search(r'^if \[\[.*?; then\n# macOS admin -> physical iPhone joiner\.',
                  SOURCE[SOURCE.index('finish_macos_mobile_direction pixel-admin-macos-joiner'):], re.M | re.S)[0]
apple = apple[:apple.index('# macOS admin')]
iphone_reverse = SOURCE.split('# Physical iPhone admin -> macOS joiner.\n', 1)[1]
iphone_reverse = re.search(r'^if \[\[.*?; then\n', iphone_reverse, re.M | re.S)[0]
for mode, reused, expected in [
    ('all', '', 'first\nreverse\napple\niphone-reverse'), ('pixel', '', 'first\nreverse'),
    ('macos-admin-iphone', '', 'apple'), ('pixel-admin-macos', '', 'reverse'),
    ('iphone-admin-macos', '', 'iphone-reverse'),
    ('all', 'retained', 'apple\niphone-reverse'),
]:
    script = selection + first + "echo first\nfi\n" + reverse + "echo reverse\nfi\n" + apple + "echo apple\nfi\n" + iphone_reverse + "echo iphone-reverse\nfi\n:"
    assert run(script, mode, reused) == expected
run(selection, 'invalid', expected=2)
reuse_guard = 'if [[ -n "$REUSE_PIXEL_RECEIPT"' + SOURCE.split('if [[ -n "$REUSE_PIXEL_RECEIPT"', 1)[1].split('\nfi\n', 1)[0] + '\nfi\n'
run(reuse_guard, 'iphone-admin-macos', expected=2,
    REUSE_PIXEL_RECEIPT='retained', ARTIFACT_ACTION='run-only')
print('PASS: actual role guards isolate either reverse direction; existing selections/reuse paths and invalid rejection preserved')

# Exercise actual iPhone requirement and Android-only artifact branch guards.
requirement = re.search(r'  \[\[ "\$MACOS_MOBILE_DIRECTIONS" == "pixel".*?\]\] \|\|', SOURCE, re.S)[0]
requirement = requirement.rsplit(' ||', 1)[0]
validation = re.search(r'  if \[\[ "\$MACOS_MOBILE_DIRECTIONS" != "pixel".*?; then\n', SOURCE, re.S)[0]
for mode in ('pixel', 'pixel-admin-macos'):
    assert run(requirement + '\n' + validation + 'echo ios\nelse\necho android\nfi', mode, IOS_DEVICE='') == 'android'
run(requirement, 'all', IOS_DEVICE='', expected=1)
assert run(requirement + '\n' + validation + 'echo ios\nelse\necho android\nfi', 'all', IOS_DEVICE='fixture') == 'ios'
run(requirement, 'iphone-admin-macos', IOS_DEVICE='', expected=1)
assert run(requirement + '\n' + validation + 'echo ios\nelse\necho android\nfi', 'iphone-admin-macos', IOS_DEVICE='fixture') == 'ios'
print('PASS: Pixel reverse needs only Android; iPhone reverse and all require iPhone and validate both mobile artifacts')

result_boundary = SOURCE.split('if ((macos_admin_android_status != 0 \\\n', 1)[1]
result_boundary = 'if ((macos_admin_android_status != 0 \\\n' + result_boundary.split('if [[ "$MACOS_MOBILE_DIRECTIONS" == "all" ]]; then', 1)[0]
for mode in ('pixel-admin-macos', 'macos-admin-iphone', 'iphone-admin-macos'):
    assert run(result_boundary + 'echo FULL_SUMMARY_PATH', mode) == 'MACOS_MOBILE_JOIN_DIAGNOSTIC_OK ' + mode
for mode in ('all', 'pixel'):
    assert run(result_boundary + 'echo FULL_SUMMARY_PATH', mode) == 'FULL_SUMMARY_PATH'
run(result_boundary + 'echo FALSE_SUCCESS', 'pixel-admin-macos', status=7, expected=1)
run(result_boundary + 'echo FALSE_SUCCESS', 'iphone-admin-macos', ios_status=7, expected=1)
print('PASS: isolated success exits before full-summary writer; failed reverse never emits diagnostic success; normal summary paths preserved')

record = SOURCE.split('android_admin_macos_status=$?\nset -e\n', 1)[1]
record = record.split('if ((android_admin_macos_status != 0)); then', 1)[0]
with tempfile.TemporaryDirectory(prefix='nvpn-reverse-exit-') as temporary:
    directory = Path(temporary)
    (directory / 'macos').mkdir()
    for status in (0, 7):
        run(record, 'pixel-admin-macos', status=status, RESULT_DIR=str(directory),
            REMOTE_ACTION_HELPER=str(ROOT / 'macos_release_action.py'))
        assert json.loads((directory / 'macos/pixel-admin-macos-direction.json').read_text()) == {
            'direction': 'pixel-admin-macos', 'exitCode': status}
print('PASS: actual canonical record call and existing atomic helper persist real zero/nonzero direction status; no device/VM calls')

record = SOURCE.split('ios_admin_macos_status=$?\nset -e\n', 1)[1]
record = record.split('if ((ios_admin_macos_status != 0)); then', 1)[0]
with tempfile.TemporaryDirectory(prefix='nvpn-iphone-reverse-exit-') as temporary:
    directory = Path(temporary)
    (directory / 'macos').mkdir()
    for status in (0, 7):
        run(record, 'iphone-admin-macos', ios_status=status, RESULT_DIR=str(directory),
            REMOTE_ACTION_HELPER=str(ROOT / 'macos_release_action.py'))
        assert json.loads((directory / 'macos/iphone-admin-macos-direction.json').read_text()) == {
            'direction': 'iphone-admin-macos', 'exitCode': status}
print('PASS: canonical iPhone reverse records its actual direction exit without a full-gate summary')
