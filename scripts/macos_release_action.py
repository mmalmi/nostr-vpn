#!/usr/bin/env python3
"""Record a remote release action and independently observe its terminal group."""

import ctypes
import hashlib
import json
import os
import pathlib
import re
import runpy
import signal
import subprocess
import sys
import time
from pathlib import Path


def write(path, value):
    temporary = path.with_suffix(".tmp")
    with temporary.open("x") as output:
        os.chmod(temporary, 0o600)
        json.dump(value, output, sort_keys=True)
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())
    temporary.replace(path)
    descriptor = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)



_cancellation = {}

def arm_deadline(deadline, cleanup_reserve=30, shared_state=None):
    """Interrupt blocking Python/syscall work before the original end budget."""
    global _cancellation
    _cancellation = shared_state if shared_state is not None else {}
    _cancellation.setdefault('signal',None)
    _cancellation['deadline']=deadline
    def cancelled(signum, _frame):
        _cancellation['signal']=_cancellation['signal'] or signum
        _cancellation['observedAtMonotonic']=time.monotonic()
        signal.setitimer(signal.ITIMER_REAL,max(.001,deadline-time.monotonic()-.25))
        raise InterruptedError('operation cancellation signal %s' % signum)
    for signum in (signal.SIGTERM,signal.SIGINT,signal.SIGHUP,signal.SIGALRM):
        signal.signal(signum,cancelled)
    reserve=.25 if _cancellation['signal'] else cleanup_reserve
    signal.setitimer(signal.ITIMER_REAL,max(.001,deadline-time.monotonic()-reserve))

def remaining(deadline, maximum=None, reserve=1):
    value = deadline - time.monotonic() - reserve
    if value <= 0:
        raise TimeoutError('original operation deadline exhausted')
    return min(value, maximum) if maximum is not None else value

def file_hash(path, deadline):
    digest = hashlib.sha256()
    with Path(path).open('rb') as source:
        while True:
            remaining(deadline)
            chunk = source.read(1024**2)
            if not chunk: break
            digest.update(chunk)
    remaining(deadline)
    return digest.hexdigest()

def read_identity(pid, executable, expected_hash, expected_args, expected_uid, deadline):
    def ps(field):
        return subprocess.check_output(['ps', '-ww', '-p', str(pid), '-o', field+'='], text=True, timeout=remaining(deadline, 3)).strip()
    start = ps('lstart')
    assert int(ps('uid')) == expected_uid and ps('command') == expected_args
    buffer = ctypes.create_string_buffer(4096)
    remaining(deadline)
    assert ctypes.CDLL('/usr/lib/libproc.dylib').proc_pidpath(pid, buffer, len(buffer)) > 0
    path = Path(executable)
    assert buffer.value.decode() == str(path) and path.resolve(strict=True) == path
    info = path.stat()
    assert file_hash(path, deadline) == expected_hash
    value = {'pid': pid, 'start': start, 'uid': expected_uid, 'pgid': os.getpgid(pid),
             'session': os.getsid(pid), 'args': expected_args, 'kernelExecutablePath': buffer.value.decode(),
             'executableSha256': expected_hash, 'executableDevice': info.st_dev, 'executableInode': info.st_ino}
    assert ps('lstart') == start and ps('command') == expected_args
    return value


def receipt_path(relative):
    if not re.fullmatch(
        r"\.cache/nvpn-release-mobile-join-actions/[0-9A-Fa-f-]{36}/[0-9A-Fa-f-]{36}",
        relative,
    ):
        raise ValueError("invalid remote action receipt path")
    path = pathlib.Path.home() / relative
    if path.resolve() != path:
        raise ValueError("remote action receipt crosses a symlink")
    return path


def baseline_snapshot(owner, pid, executable, arguments):
    deadline = time.monotonic() + 10
    arm_deadline(deadline, cleanup_reserve=.25)
    try:
        original = read_identity(pid, executable, file_hash(executable, deadline),
                                 arguments, os.getuid(), deadline)
        write(owner / "baseline.json", original)
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)


def ownership_files(owner):
    if owner.resolve(strict=True) != owner or not owner.is_dir():
        raise ValueError("baseline ownership path changed")
    result = {}
    for path in owner.iterdir():
        if (path.name not in {"acquired", "prior-state", "baseline.json", "restored-record"}
                or path.is_symlink() or not path.is_file()):
            raise ValueError("unexpected baseline ownership entry")
        result[path.name] = hashlib.sha256(path.read_bytes()).hexdigest()
    return result


def baseline_restore(owner, executable, process_name):
    # The prior restore already had a ten-second launch/readback allowance.
    # Use one absolute end for launch, recovery and post-action handoff.
    deadline = time.monotonic() + 10
    arm_deadline(deadline, cleanup_reserve=6)
    native = runpy.run_path(str(Path(__file__).with_name("native-lab.py")))
    record = Path(os.environ["NVPN_MACOS_RELEASE_ACTION_DIR"]) / "restored-baseline.json"
    state = {"phase": "launch_pending", "owner": str(owner),
             "deadlineMonotonic": deadline, "processName": process_name}
    child = None
    launch_recorded = False
    try:
        if record.exists():
            print("existing restoration evidence is retained", file=sys.stderr)
            return 125
        if (owner / "restored-record").exists():
            raise ValueError("previous restoration is unresolved; no second launch")
        prior = (owner / "prior-state").read_text().strip()
        if prior not in ("absent", "hidden", "visible") or not (owner / "acquired").is_file():
            raise ValueError("baseline ownership is incomplete")
        probe = subprocess.run(["pgrep", "-x", process_name], capture_output=True,
                               text=True, timeout=remaining(deadline, 3))
        if probe.returncode != 1 or probe.stdout.strip() or probe.stderr.strip():
            raise ValueError("unexpected app before exact baseline restoration")
        state["priorState"] = prior
        original = None if prior == "absent" else json.loads((owner / "baseline.json").read_text())
        state["original"] = original
        write(record, state)
        write(owner / "restored-record", {"path": str(record)})
        state["ownerFiles"] = ownership_files(owner)
        write(record, state)
        if original is not None:
            arguments = executable + (" --hidden" if prior == "hidden" else "")
            if (original["kernelExecutablePath"] != executable
                    or original["args"] != arguments or original["uid"] != os.getuid()):
                raise ValueError("baseline launch does not match its original identity")
            user = os.environ.get("USER") or "dev"
            environment = {"HOME": os.environ["HOME"], "USER": user,
                "LOGNAME": os.environ.get("LOGNAME") or user,
                "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                "TMPDIR": os.environ.get("TMPDIR") or "/tmp",
                "LANG": os.environ.get("LANG") or "en_US.UTF-8"}
            remaining(deadline)
            # Same qualified protection as the accepted restoration boundary:
            # capture the returned handle/phase before observing cancellation.
            with native["DeferredSignals"]() as launch_signals:
                previous_alarm = signal.getsignal(signal.SIGALRM)
                def launch_alarm(signum, frame):
                    _cancellation["signal"] = _cancellation.get("signal") or signum
                    _cancellation["observedAtMonotonic"] = time.monotonic()
                    signal.setitimer(signal.ITIMER_REAL, max(.001, deadline - time.monotonic() - .25))
                    launch_signals._handle(signum, frame)
                signal.signal(signal.SIGALRM, launch_alarm)
                try:
                    child = subprocess.Popen([executable] + (["--hidden"] if prior == "hidden" else []),
                        env=environment, start_new_session=True, stdin=subprocess.DEVNULL,
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    state.update(pid=child.pid, phase="launched_identity_unresolved")
                finally:
                    signal.signal(signal.SIGALRM, previous_alarm)
            if launch_signals.received is not None:
                state["cancellation"] = dict(_cancellation, launchSignal=launch_signals.received)
                raise InterruptedError("cancellation during baseline launch")
            write(record, state)
            launch_recorded = True
            last_error = None
            for _ in range(30):
                try:
                    identity = read_identity(child.pid, executable, original["executableSha256"],
                                             original["args"], original["uid"], deadline)
                    break
                except (InterruptedError, TimeoutError):
                    raise
                except Exception as error:
                    last_error = error
                    time.sleep(remaining(deadline, .1))
            else:
                raise RuntimeError("exact launched baseline identity is unresolved") from last_error
            if identity["pgid"] != identity["session"] or identity["pgid"] != child.pid:
                raise ValueError("baseline did not enter its own session")
            for key in ("executableDevice", "executableInode"):
                if identity[key] != original[key]:
                    raise ValueError("baseline executable identity changed")
            state["identity"] = identity
        state["phase"] = "identity_verified_ownership_retained"
        write(record, state)
        return 0
    except BaseException as error:
        # If persistence failed, close only the returned, still-owned launch
        # handle using the remaining original budget; never launch a replacement.
        signal.setitimer(signal.ITIMER_REAL, max(.001, deadline - time.monotonic() - .25))
        if child is not None and not launch_recorded:
            try:
                with native["DeferredSignals"]():
                    escalated, reaped = native["stop_managed_process_group"](
                        child, signal.SIGTERM, min(1, remaining(deadline, reserve=5.5)))
                    state["unrecordedLaunchClosure"] = {
                        "pid": child.pid, "escalated": escalated,
                        "processGroupReaped": reaped, "exitCode": child.poll()}
            except BaseException as cleanup_error:
                state["unrecordedLaunchClosure"] = {
                    "pid": child.pid, "error": repr(cleanup_error), "processGroupReaped": False}
        state.update(phase="unresolved", error=repr(error))
        print(json.dumps({"baselineRecovery": state}), flush=True)
        try:
            write(record, state)
        except BaseException as persistence_error:
            print(repr(persistence_error), file=sys.stderr)
        return 125
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)


def baseline_handoff(path):
    record = path / "restored-baseline.json"
    if not record.exists():
        return
    state = json.loads(record.read_text())
    print(json.dumps({"baselineRestoration": state}), flush=True)
    if state.get("phase") != "identity_verified_ownership_retained":
        raise ValueError("baseline restoration is unresolved")
    deadline = state["deadlineMonotonic"]
    arm_deadline(deadline, cleanup_reserve=.25)
    try:
        owner = Path(state["owner"])
        identity = state.get("identity")
        def observe():
            if identity is None:
                probe = subprocess.run(["pgrep", "-x", state["processName"]],
                    capture_output=True, text=True, timeout=remaining(deadline, 3))
                if probe.returncode != 1 or probe.stdout.strip() or probe.stderr.strip():
                    raise ValueError("absent baseline changed before handoff")
                return None
            current = read_identity(identity["pid"], identity["kernelExecutablePath"],
                identity["executableSha256"], identity["args"], identity["uid"], deadline)
            if current != identity:
                raise ValueError("exact restored baseline changed before handoff")
            return current
        state["identityAfterActionClosure"] = observe()
        if ownership_files(owner) != state["ownerFiles"]:
            raise ValueError("baseline ownership changed before release")
        state["phase"] = "handoff_pending"
        write(record, state)
        for name in state["ownerFiles"]:
            (owner / name).unlink()
        owner.rmdir()
        state["identityAfterOwnershipRelease"] = observe()
        state["phase"] = "handed_off"
        write(record, state)
        print(json.dumps({"baselineHandoff": state}), flush=True)
    except BaseException as error:
        state.update(phase="handoff_unresolved", error=repr(error))
        print(json.dumps({"baselineRecovery": state}), flush=True)
        write(record, state)
        raise
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)


def run(path, action, command):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.mkdir(mode=0o700)
    pid = os.getpid()
    if os.getpgrp() != pid:
        os.setsid()
    identity = subprocess.run(
        ["ps", "-p", str(pid), "-o", "lstart=", "-o", "uid=,command="],
        capture_output=True, text=True, timeout=2, check=True,
    ).stdout.strip()
    start = subprocess.run(
        ["ps", "-p", str(pid), "-o", "lstart="],
        capture_output=True, text=True, timeout=2, check=True,
    ).stdout.strip()
    if not identity or not start or os.getpgrp() != pid:
        raise ValueError("remote action identity is incomplete")
    write(path / "identity.json", {
        "pid": pid, "start": start, "pgid": os.getpgrp(),
        "uid": os.getuid(), "command": identity, "action": action,
        "commandSha256": hashlib.sha256(command.encode()).hexdigest(),
    })
    # Keep the command, its drivers, and their children in this SSH action's
    # group. A lost transport or interrupted supervisor leaves an unclosed
    # receipt; it never launches another cleanup operation.
    environment = dict(os.environ, NVPN_MACOS_RELEASE_ACTION_DIR=str(path))
    result = subprocess.run(["/bin/bash", "-c", command], env=environment)
    status = result.returncode if result.returncode >= 0 else 128 - result.returncode
    write(path / "result.json", {
        "childExitCode": result.returncode, "exitCode": status,
    })
    return status


def closed(path, action, command_sha, transport_status):
    identity = json.loads((path / "identity.json").read_text())
    result = json.loads((path / "result.json").read_text())
    print(json.dumps({"identity": identity, "result": result}), flush=True)
    if (
        identity.get("action") != action
        or identity.get("commandSha256") != command_sha
        or identity.get("uid") != os.getuid()
        or not identity.get("start") or not identity.get("command")
        or type(identity.get("pid")) is not int or identity["pid"] <= 1
        or type(identity.get("pgid")) is not int or identity["pgid"] <= 1
        or type(result.get("childExitCode")) is not int
        or type(result.get("exitCode")) is not int
        or not 0 <= result["exitCode"] <= 255
        or identity["pgid"] != identity["pid"]
        or result["exitCode"] != transport_status
        or result["exitCode"] != (
            result["childExitCode"] if result["childExitCode"] >= 0
            else 128 - result["childExitCode"]
        )
    ):
        raise ValueError("remote action completion does not match its intent")
    # Prove terminal action closure before verifying a separately restored
    # baseline and releasing its exact retained ownership records.
    end = time.monotonic() + 2
    while True:
        process = subprocess.run(
            ["ps", "-p", str(identity["pid"]), "-o", "lstart="],
            capture_output=True, text=True, timeout=1,
        )
        gone = process.returncode == 1 or (
            process.returncode == 0 and process.stdout.strip() != identity["start"]
        )
        try:
            os.killpg(identity["pgid"], 0)
            group_gone = False
        except ProcessLookupError:
            group_gone = True
        if gone and group_gone or time.monotonic() >= end:
            print(json.dumps({
                "psExit": process.returncode, "psStdout": process.stdout,
                "psStderr": process.stderr, "groupGone": group_gone,
            }), flush=True)
        if gone and group_gone:
            if result["exitCode"] == 0:
                baseline_handoff(path)
            return 0
        if time.monotonic() >= end:
            raise ValueError("remote action or group is still active")
        time.sleep(.05)


def main():
    if len(sys.argv) == 6 and sys.argv[1] == "baseline-snapshot":
        baseline_snapshot(Path(sys.argv[2]), int(sys.argv[3]), sys.argv[4], sys.argv[5])
        return 0
    if len(sys.argv) == 5 and sys.argv[1] == "baseline-restore":
        return baseline_restore(Path(sys.argv[2]), sys.argv[3], sys.argv[4])
    if len(sys.argv) == 4 and sys.argv[1] == "record":
        write(pathlib.Path(sys.argv[2]), json.loads(sys.argv[3]))
        return 0
    mode, relative, action, value, *extra = sys.argv[1:]
    path = receipt_path(relative)
    if mode == "run" and not extra:
        return run(path, action, value)
    if mode == "closed" and len(extra) == 1:
        return closed(path, action, value, int(extra[0]))
    raise ValueError("invalid remote release action invocation")


if __name__ == "__main__":
    sys.exit(main())
