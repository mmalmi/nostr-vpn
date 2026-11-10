#!/usr/bin/env python3
"""Exercise full canonical restoration under tracked remote actions, locally."""
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
import threading
import time
import uuid

ROOT = pathlib.Path(__file__).resolve().parent
HELPER = ROOT / "macos_release_action.py"
LIBRARY = ROOT / "lib-macos-release-app-ownership.sh"
CASES = ("success", "post-action-identity", "record", "identity", "term", "alarm", "absent",
         "relative", "blocked-read")
selected = tuple(sys.argv[1:]) or CASES
assert all(case in CASES for case in selected)


def run(argv, expected=0, **kwargs):
    result = subprocess.run(argv, capture_output=True, text=True, timeout=15, **kwargs)
    accepted = expected if isinstance(expected, tuple) else (expected,)
    assert result.returncode in accepted, (result.returncode, result.stdout, result.stderr)
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
    closure_fault = root / "closure-fault.py"
    closure_fault.write_text('''import importlib.util,pathlib,sys
helper,relative,command_sha,deadline,fifo=sys.argv[1:]
spec=importlib.util.spec_from_file_location('action_under_test',helper)
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
original=pathlib.Path.read_text
def blocked_read(path,*args,**kwargs):
 if path.name=='identity.json':
  with open(fifo) as source: source.read()
 return original(path,*args,**kwargs)
pathlib.Path.read_text=blocked_read
sys.exit(m.closed(pathlib.Path.home()/relative,'fixture',command_sha,0,float(deadline)))
''')
    deadlines = {}

    def action(command, status=0):
        relative = f".cache/nvpn-release-mobile-join-actions/{uuid.uuid4()}/{uuid.uuid4()}"
        result = run([sys.executable, str(HELPER), "run", relative, "fixture", command],
                     expected=status, env=env)
        stderr_path = root / relative / "action-stderr.log"
        stderr_path.write_text(result.stderr)
        deadlines[relative] = run([sys.executable, str(HELPER), "completion-deadline",
            str(stderr_path), "fixture", hashlib.sha256(command.encode()).hexdigest(),
            str(status)], env=env).stdout.strip()
        return relative, result

    def close(relative, command, status=0, expected=0):
        return run([sys.executable, str(HELPER), "closed", relative, "fixture",
                    hashlib.sha256(command.encode()).hexdigest(), str(status), deadlines[relative]],
                   expected=expected, env=env)

    def stop(pid):
        try:
            os.killpg(pid, signal.SIGTERM)
        except ProcessLookupError:
            return
        deadline = time.clock_gettime(time.CLOCK_MONOTONIC) + 3
        while time.clock_gettime(time.CLOCK_MONOTONIC) < deadline:
            try:
                os.killpg(pid, 0)
            except ProcessLookupError:
                return
            time.sleep(.02)
        raise AssertionError("exact fixture group did not close")

    for case in selected:
        owner = root / case
        setup = f'''cd {shlex.quote(str(root))}
source {shlex.quote(str(LIBRARY))}
MACOS_RELEASE_APP_STATE_DIR={shlex.quote(owner.name if case == "relative" else str(owner))}
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
            elif case == "blocked-read":
                original = record_path.read_bytes()
                deadline = record["deadlineMonotonic"]
                assert float(deadlines[relative]) == deadline
                fifo = root / "blocked-receipt"
                os.mkfifo(fifo)
                descriptor = os.open(fifo, os.O_RDWR | os.O_NONBLOCK)
                try:
                    # Consume the original budget before entering closure;
                    # this must not turn into another ten-second allowance.
                    time.sleep(max(0, deadline - time.clock_gettime(time.CLOCK_MONOTONIC) - 1.5))
                    started = time.clock_gettime(time.CLOCK_MONOTONIC)
                    result = run([sys.executable, str(closure_fault), str(HELPER), relative,
                        hashlib.sha256(command.encode()).hexdigest(), deadlines[relative],
                        str(fifo)], expected=(1, -signal.SIGALRM), env=env)
                    ended = time.clock_gettime(time.CLOCK_MONOTONIC)
                    assert "operation cancellation signal" in result.stderr
                    assert deadline - .5 <= ended <= deadline + .5, (deadline, started, ended)
                    assert ended - started < 2
                finally:
                    os.close(descriptor)
                assert owner.is_dir() and record_path.read_bytes() == original
                assert "identityAfterActionClosure" not in record
                os.kill(restored_pid, 0)
                # Expired closure and another restore cannot release ownership
                # or overwrite the first record or launch a replacement.
                close(relative, command, expected=(1, -signal.SIGALRM))
                repeated, _ = action(setup + "macos_release_app_restore", 125)
                assert "pid" not in json.loads((root / repeated / "restored-baseline.json").read_text())
                close(repeated, setup + "macos_release_app_restore", 125)
                assert owner.is_dir() and record_path.read_bytes() == original
                print("blocked-read: original deadline cancelled closure; ownership and exact record retained")
            else:
                assert record["phase"] == "identity_verified_ownership_retained"
                close(relative, command)
                handed = json.loads(record_path.read_text())
                assert handed["phase"] == "handed_off" and not owner.exists()
                if case in ("success", "relative"):
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

    # Exercise the changed host transport callsite using its actual functions,
    # including rejection before closure when completion output is ambiguous.
    source = (ROOT / "macos-vm-release-mobile-join-e2e.sh").read_text()
    functions = "\n".join(re.search(r"^" + name + r"\(\) \{\n.*?^\}\n", source,
        re.M | re.S)[0] for name in ("macos_remote_actions_block",
        "macos_remote_actions_closed", "macos_remote_action"))
    host_actions = root / "host-actions"
    host_actions.mkdir()
    shell = f'''set -euo pipefail
{functions}
REMOTE_ACTION_HELPER={shlex.quote(str(HELPER))}
REMOTE_ACTION_SESSION={uuid.uuid4()}
REMOTE_ACTION_DIR={shlex.quote(str(host_actions))}
MAC_HOST=fixture
ssh() {{ local command="${{!#}}"; bash -c "$command"; }}
macos_remote_action fixture 'exit 0'
macos_remote_actions_closed
'''
    run(["bash", "-c", shell], env=env)
    assert len(list(host_actions.glob("*.closed.json"))) == 1
    bad_shell = shell + '''macos_remote_action fixture 'echo "NVPN_REMOTE_ACTION_COMPLETE {}" >&2'
echo unexpected-continuation
'''
    failed = run(["bash", "-c", bad_shell], expected=1, env=env)
    assert "unexpected-continuation" not in failed.stdout
    assert (host_actions / "blocked.json").is_file()
    assert len(list(host_actions.glob("*.closed.json"))) == 2
    print("host deadline transport: actual success and ambiguous-completion rejection passed")

print(f"Mac baseline handoff: {len(selected)} full-restore boundaries passed ({', '.join(selected)}); exact owned fixture groups closed")
