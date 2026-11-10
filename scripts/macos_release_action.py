#!/usr/bin/env python3
"""Record a remote release action and independently observe its terminal group."""

import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys
import time


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
    result = subprocess.run(["/bin/bash", "-c", command])
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
    # This observation is inside the caller's original finite phase; no signal,
    # retry, profile reset, restoration, or deletion is performed here.
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
            return 0
        if time.monotonic() >= end:
            raise ValueError("remote action or group is still active")
        time.sleep(.05)


def main():
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
