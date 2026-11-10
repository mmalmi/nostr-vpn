#!/usr/bin/env python3
"""Exercise full canonical restoration under tracked remote actions, locally."""
import hashlib
import json
import os
import pathlib
import shlex
import signal
import subprocess
import sys
import tempfile
import threading
import time
import uuid

ROOT = pathlib.Path(__file__).resolve().parent
HELPER = ROOT / "macos_release_action.py"
LIBRARY = ROOT / "lib-macos-release-app-ownership.sh"


def run(argv, expected=0, **kwargs):
    result = subprocess.run(argv, capture_output=True, text=True, timeout=15, **kwargs)
    assert result.returncode == expected, (result.returncode, result.stdout, result.stderr)
    return result


with tempfile.TemporaryDirectory(prefix="nvpn-baseline-handoff-") as temporary:
    root = pathlib.Path(temporary).resolve()
    env = dict(os.environ, HOME=str(root))
    name = f"NvBh{os.getpid()}"
    executable = root / name
    run(["xcrun", "clang", "-x", "c", "-", "-o", str(executable)],
        input="#include <unistd.h>\nint main(void) { for (;;) pause(); }\n")
    fault_source = root / "fault.py"
    fault_source.write_text('''import importlib.util,os,pathlib,signal,sys
fault,helper,mode,owner,executable,name=sys.argv[1:]
spec=importlib.util.spec_from_file_location('action_under_test',helper)
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
assert mode=='baseline-restore'
if fault=='record':
 original=m.write
 def write(path,value):
  if value.get('phase')=='launched_identity_unresolved': raise OSError('injected launch-record failure')
  return original(path,value)
 m.write=write
elif fault=='identity':
 def read_identity(*args): raise ValueError('injected exact identity failure')
 m.read_identity=read_identity
elif fault in ('term','alarm'):
 original=m.subprocess.Popen
 def launch(argv,*args,**kwargs):
  child=original(argv,*args,**kwargs)
  if argv[0]==executable:
   os.kill(os.getpid(),signal.SIGTERM if fault=='term' else signal.SIGALRM)
  return child
 m.subprocess.Popen=launch
sys.exit(m.baseline_restore(pathlib.Path(owner),executable,name))
''')

    def action(command, status=0):
        relative = f".cache/nvpn-release-mobile-join-actions/{uuid.uuid4()}/{uuid.uuid4()}"
        result = run([sys.executable, str(HELPER), "run", relative, "fixture", command],
                     expected=status, env=env)
        return relative, result

    def close(relative, command, status=0, expected=0):
        return run([sys.executable, str(HELPER), "closed", relative, "fixture",
                    hashlib.sha256(command.encode()).hexdigest(), str(status)],
                   expected=expected, env=env)

    def stop(pid):
        try:
            os.killpg(pid, signal.SIGTERM)
        except ProcessLookupError:
            return
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            try:
                os.killpg(pid, 0)
            except ProcessLookupError:
                return
            time.sleep(.02)
        raise AssertionError("exact fixture group did not close")

    for case in ("success", "post-action-identity", "record", "identity", "term", "alarm", "absent"):
        owner = root / case
        setup = f'''source {shlex.quote(str(LIBRARY))}
MACOS_RELEASE_APP_STATE_DIR={shlex.quote(str(owner))}
MACOS_RELEASE_APP_INSTALLED_EXE={shlex.quote(str(executable))}
MACOS_RELEASE_APP_GATE_EXE=unused-fixture
MACOS_RELEASE_APP_PROCESS_NAME={name}
'''
        initial = None
        restored_pid = None
        try:
            if case != "absent":
                initial = subprocess.Popen([str(executable), "--hidden"],
                    start_new_session=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                reaper = threading.Thread(target=initial.wait, daemon=True)
                reaper.start()
            acquire_command = setup + "macos_release_app_acquire"
            acquired, _ = action(acquire_command)
            close(acquired, acquire_command)
            if initial is not None:
                reaper.join(2)
                assert initial.returncode == -signal.SIGTERM
                assert json.loads((owner / "baseline.json").read_text())["pid"] == initial.pid
            command = setup
            failure = case in ("record", "identity", "term", "alarm")
            if failure:
                command += f'''python3() {{
 if [[ "$2" == baseline-restore ]]; then
  command python3 {shlex.quote(str(fault_source))} {case} "$@"
 else
  command python3 "$@"
 fi
}}
'''
            command += "macos_release_app_restore"
            relative, _ = action(command, 125 if failure else 0)
            record_path = root / relative / "restored-baseline.json"
            record = json.loads(record_path.read_text())
            restored_pid = record.get("pid")
            assert owner.is_dir(), "ownership released before action closure"
            assert pathlib.Path(json.loads((owner / "restored-record").read_text())["path"]) == record_path
            if failure:
                assert record["phase"] == "unresolved"
                if case in ("record", "term", "alarm"):
                    assert record["unrecordedLaunchClosure"]["pid"] == restored_pid
                    assert record["unrecordedLaunchClosure"]["processGroupReaped"] is True
                else:
                    os.kill(restored_pid, 0)
                close(relative, command, 125)
                assert owner.is_dir()
                # Another full restore cannot launch again or overwrite the
                # first action's durable recovery record.
                original = record_path.read_bytes()
                repeat_command = setup + "macos_release_app_restore"
                repeated, _ = action(repeat_command, 125)
                assert record_path.read_bytes() == original
                assert "pid" not in json.loads((root / repeated / "restored-baseline.json").read_text())
                close(repeated, repeat_command, 125)
            elif case == "post-action-identity":
                stop(restored_pid)
                close(relative, command, expected=1)
                assert owner.is_dir()
                assert json.loads(record_path.read_text())["phase"] == "handoff_unresolved"
            else:
                assert record["phase"] == "identity_verified_ownership_retained"
                close(relative, command)
                handed = json.loads(record_path.read_text())
                assert handed["phase"] == "handed_off" and not owner.exists()
                if case == "success":
                    identity = handed["identity"]
                    assert identity["pid"] == identity["pgid"] == identity["session"] == restored_pid
                    assert handed["identityAfterActionClosure"] == identity
                    assert handed["identityAfterOwnershipRelease"] == identity
                    os.kill(restored_pid, 0)
                else:
                    assert handed["identityAfterActionClosure"] is None
        finally:
            if initial is not None and initial.poll() is None:
                stop(initial.pid)
            if restored_pid is not None:
                stop(restored_pid)

print("Mac baseline handoff: 7 full-restore boundaries passed; exact owned fixture groups closed")
