#!/usr/bin/env python3
"""Exercise action closure and cleanup ordering without a VM or phone."""
import hashlib
import json
import os
import pathlib
import re
import shlex
import signal
import subprocess
import sys
import tempfile
import time
import uuid

ROOT = pathlib.Path(__file__).resolve().parent
HELPER = ROOT / "macos_release_action.py"
HOST = (ROOT / "macos-vm-release-mobile-join-e2e.sh").read_text()
REMOTE = (ROOT / "macos-release-mobile-join-remote.sh").read_text()


def function(source, name):
    return re.search(r"^" + name + r"\(\) \{\n.*?^\}\n", source, re.M | re.S)[0]


def run(argv, *, expected=0, **kwargs):
    result = subprocess.run(argv, capture_output=True, text=True, timeout=12, **kwargs)
    assert result.returncode == expected, (argv[0], result.returncode, result.stdout, result.stderr)
    return result


with tempfile.TemporaryDirectory(prefix="nvpn-action-closure-") as temporary:
    directory = pathlib.Path(temporary).resolve()
    env = dict(os.environ, HOME=str(directory))
    actions = directory / "actions"
    actions.mkdir()
    shell_functions = "\n".join(function(HOST, name) for name in (
        "macos_remote_actions_block", "macos_remote_actions_closed",
        "macos_remote_action", "cleanup", "macos_mobile_direction_cleanup",
        "finish_macos_mobile_direction", "install_remote_harness", "remove_remote_harness",
    ))
    shell_prefix = f'''set -euo pipefail
{shell_functions}
ROOT={shlex.quote(str(ROOT.parent))}
REMOTE_ACTION_HELPER={shlex.quote(str(HELPER))}
REMOTE_ACTION_SESSION={uuid.uuid4()}
REMOTE_ACTION_DIR={shlex.quote(str(actions))}
MAC_HOST=fixture
RESULT_DIR={shlex.quote(str(directory))}
PRIVATE_DIR="$RESULT_DIR/private"
mkdir -p "$PRIVATE_DIR" "$RESULT_DIR/macos"
events="$RESULT_DIR/events"
: >"$events"
remote_pid=""
remote_pid_owner=""
acceptance_observer_pids=()
remote_app_ownership_armed=1
remote_harness_install_attempted=1
MACOS_MOBILE_DIRECTION_LABEL=fixture
release_join_android_capture_failure_log() {{ :; }}
release_join_android_stop() {{ echo android-stop >>"$events"; }}
remote() {{ macos_remote_actions_closed || return 1; echo "$1" >>"$events"; }}
remove_remote_harness() {{ echo remove-harness >>"$events"; }}
'''

    def shell(body, expected=0):
        return run(["bash", "-c", shell_prefix + body], expected=expected, env=env)

    # A local SSH exit is insufficient: unresolved remote work must prevent
    # parent reset/reversal, EXIT restoration, and harness/evidence deletion.
    intent = actions / "pending.intent.json"
    intent.write_text("{}\n")
    shell('''set +e
(false; macos_mobile_direction_cleanup)
set -e
finish_macos_mobile_direction fixture
echo reverse >>"$events"
''', expected=1)
    assert not (directory / "events").read_text()
    shell("cleanup", expected=1)
    assert not (directory / "events").read_text()
    assert (directory / "private").is_dir()
    intent.unlink()
    (actions / "blocked.json").unlink()

    # Failed local stop also blocks continuation, even before any remote intent.
    for cleanup_function in ("macos_mobile_direction_cleanup", "cleanup"):
        shell(f'''remote_pid=12345
remote_pid_owner=67890
macos_release_stop_owned_child() {{ return 1; }}
{cleanup_function}
''', expected=1)
        assert not (directory / "events").read_text()
        assert (directory / "private").is_dir()
        assert (actions / "blocked.json").is_file()
        (actions / "blocked.json").unlink()

    # Lost transport preserves its original status and blocks the next action.
    shell('''ssh() { return 255; }
set +e
macos_remote_action manual-join 'exit 0'
set -e
macos_remote_action reset-profile 'exit 0'
echo reverse >>"$events"
''', expected=1)
    transport = list(actions.glob("*.transport.json"))
    assert len(transport) == 1
    assert json.loads(transport[0].read_text()) == {"sshExitCode": 255}
    assert not (directory / "events").read_text()
    for path in actions.iterdir():
        path.unlink()

    # Real supervisors and process-group observations under a temporary HOME.
    def action(command, status):
        relative = f".cache/nvpn-release-mobile-join-actions/{uuid.uuid4()}/{uuid.uuid4()}"
        run([sys.executable, str(HELPER), "run", relative, "fixture", command],
            expected=status, env=env)
        return relative

    def closed(relative, command, status, expected=0):
        return run([sys.executable, str(HELPER), "closed", relative, "fixture",
                    hashlib.sha256(command.encode()).hexdigest(), str(status), "none"],
                   expected=expected, env=env)

    for status in (0, 7):
        command = f"exit {status}"
        relative = action(command, status)
        closed(relative, command, status)
    receipt = directory / relative
    (receipt / "result.json").write_text('{"exitCode":true,"childExitCode":7}')
    closed(relative, command, status, 1)
    (receipt / "result.json").write_text('{"exitCode":7,"childExitCode":7}')
    closed(relative, command, 255, 1)
    (receipt / "result.json").unlink()
    closed(relative, command, status, 1)

    # A successful shell exit cannot conceal its still-running background child.
    sleeper = None
    try:
        command = "sleep 20 </dev/null >/dev/null 2>&1 &"
        relative = action(command, 0)
        identity = json.loads((directory / relative / "identity.json").read_text())
        sleeper = identity["pgid"]
        closed(relative, command, 0, 1)
    finally:
        if sleeper is not None:
            try:
                os.killpg(sleeper, signal.SIGTERM)
            except ProcessLookupError:
                pass

    # Whole host action path, including durable intent, transport and closure.
    # Proven closure permits reset, reversal, restoration and deletion.
    shell('''ssh() { local command="${!#}"; bash -c "$command"; }
macos_remote_action fixture 'exit 0'
macos_remote_actions_closed
finish_macos_mobile_direction fixture
echo reverse >>"$events"
cleanup
''')
    assert (directory / "events").read_text().splitlines() == [
        "reset-profile", "reverse", "cleanup", "remove-harness",
    ]
    assert not (directory / "private").exists()

    # A terminal supervisor does not override an unresolved guest app stop.
    shell('''ssh() { local command="${!#}"; bash -c "$command"; }
macos_remote_action fixture 'exit 125' || true
macos_remote_actions_closed
echo reverse >>"$events"
''', expected=1)
    assert not (directory / "events").read_text()
    for path in actions.iterdir():
        path.unlink()

    # The transferred harness can be removed only by its installing session.
    # Exercise the actual removal function rather than the cleanup event stub.
    remove_source = function(HOST, "remove_remote_harness")
    harness = directory / ".cache/fixture-harness"
    harness.mkdir(parents=True)
    (harness / ".owner").write_text("different-session\n")
    shell(remove_source + '''
REMOTE_HARNESS_ROOT_REL=.cache/fixture-harness
ssh() { local command="${!#}"; bash -c "$command"; }
remove_remote_harness
''', expected=1)
    assert harness.is_dir()
    shell(remove_source + '''
REMOTE_HARNESS_ROOT_REL=.cache/fixture-harness
printf '%s\n' "$REMOTE_ACTION_SESSION" >"$HOME/$REMOTE_HARNESS_ROOT_REL/.owner"
ssh() { local command="${!#}"; bash -c "$command"; }
remove_remote_harness
''')
    assert not harness.exists()
    shell(remove_source + '''
REMOTE_HARNESS_ROOT_REL=.cache/fixture-harness
REMOTE_HARNESS_FILES=(scripts/macos-release-mobile-join-remote.sh)
ssh() { local command="${!#}"; bash -c "$command"; }
install_remote_harness
cmp "$ROOT/scripts/macos-release-mobile-join-remote.sh" "$HOME/$REMOTE_HARNESS_ROOT_REL/scripts/macos-release-mobile-join-remote.sh"
macos_remote_actions_closed
remove_remote_harness
''')
    assert not harness.exists()

    # Preserve guest app ownership on stop failure; EXIT cannot retry the stop.
    owner = directory / "app-owner"
    owner.write_text("fixture")
    run(["bash", "-c", f'''set -euo pipefail
{function(REMOTE, "stop_app")}
APP_STOP_UNRESOLVED=0
APP_PID=12345
APP_EXE=fixture
OWNED_PID_FILE={shlex.quote(str(owner))}
calls=0
macos_release_app_stop_pid() {{ calls=$((calls + 1)); return 1; }}
stop_app && exit 10
stop_app && exit 11
[[ "$APP_PID" == 12345 && "$calls" -eq 1 && -f "$OWNED_PID_FILE" ]]
'''])


print("Mac remote action closure and cleanup ordering passed (no VM/device use)")

run([sys.executable, str(ROOT / "test-macos-baseline-handoff.py")])
print("Full restored-baseline handoff checks passed")
