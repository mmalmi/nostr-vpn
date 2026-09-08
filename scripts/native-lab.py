#!/usr/bin/env python3
"""Reserve native test resources and classify infrastructure failures."""

import argparse
import contextlib
import hashlib
import json
import math
import os
import platform
import signal
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path

try:
    import fcntl
except ImportError:  # pragma: no cover - managed runs and recovery reject non-POSIX hosts
    fcntl = None


INFRASTRUCTURE_UNAVAILABLE = 75
RESERVED_KINDS = {"android", "ios-device", "ios-simulator", "local", "ssh"}
DEFAULT_SIGNAL_GRACE_SECONDS = 600.0
SIGNALS_TO_DEFER = tuple(
    watched
    for name in ("SIGHUP", "SIGINT", "SIGTERM")
    if (watched := getattr(signal, name, None)) is not None
)


class DeferredSignals:
    """Record termination requests without abandoning lock-owning cleanup."""

    def __init__(self):
        self.received = None
        self.previous = {}

    def _handle(self, signum, _frame):
        if self.received is None:
            self.received = signum

    def __enter__(self):
        for watched in SIGNALS_TO_DEFER:
            self.previous[watched] = signal.getsignal(watched)
            signal.signal(watched, self._handle)
        return self

    def __exit__(self, _error_type, _error, _traceback):
        for watched, previous in self.previous.items():
            signal.signal(watched, previous)


def child_process_options():
    return {"start_new_session": True}


def process_group_exists(process):
    try:
        os.killpg(process.pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return True
    return True


def signal_process_group(process, signum):
    if not process_group_exists(process):
        return
    try:
        os.killpg(process.pid, signum)
    except ProcessLookupError:
        pass


def kill_process_group(process):
    if not process_group_exists(process):
        return
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def wait_for_process_group_exit(process, timeout):
    deadline = time.monotonic() + timeout
    while process_group_exists(process):
        process.poll()
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.01)
    return True


def stop_managed_process_group(process, cooperative_signal, grace):
    signal_process_group(process, cooperative_signal)
    if wait_for_process_group_exit(process, grace):
        return False, True
    kill_process_group(process)
    return True, wait_for_process_group_exit(process, 5)


def wait_for_managed_child(
    command, environment, timeout, signal_grace, deferred, child_started=None
):
    process = subprocess.Popen(command, env=environment, **child_process_options())
    normal_deadline = time.monotonic() + timeout if timeout else None
    termination_reason = None
    forwarded_signal = None
    escalated = False
    process_group_reaped = False
    child_code = None
    supervisor_error_type = None
    cleanup_attempted = False

    try:
        if child_started is not None:
            child_started(process)
        while True:
            now = time.monotonic()
            child_code = process.poll()
            if deferred.received is not None:
                termination_reason = "signal"
                forwarded_signal = deferred.received
                cleanup_attempted = True
                escalated, process_group_reaped = stop_managed_process_group(
                    process, forwarded_signal, signal_grace
                )
                break
            if normal_deadline is not None and now >= normal_deadline:
                termination_reason = "timeout"
                forwarded_signal = signal.SIGTERM
                cleanup_attempted = True
                escalated, process_group_reaped = stop_managed_process_group(
                    process, forwarded_signal, signal_grace
                )
                break
            if child_code is not None:
                if process_group_exists(process):
                    termination_reason = "orphaned_process_group"
                    forwarded_signal = signal.SIGTERM
                    cleanup_attempted = True
                    escalated, process_group_reaped = stop_managed_process_group(
                        process, forwarded_signal, signal_grace
                    )
                else:
                    process_group_reaped = True
                break
            wait_seconds = 0.05
            if normal_deadline is not None:
                wait_seconds = max(0.001, min(wait_seconds, normal_deadline - now))
            time.sleep(wait_seconds)
    except BaseException as error:
        termination_reason = "supervisor_error"
        supervisor_error_type = type(error).__name__
        try:
            cleanup_attempted = True
            escalated, process_group_reaped = stop_managed_process_group(
                process, signal.SIGTERM, signal_grace
            )
        except BaseException:
            cleanup_attempted = False
            process_group_reaped = False
    finally:
        if not process_group_reaped and not cleanup_attempted:
            try:
                extra_escalated, process_group_reaped = stop_managed_process_group(
                    process, signal.SIGTERM, signal_grace
                )
                escalated = escalated or extra_escalated
            except BaseException:
                process_group_reaped = False

    child_code = process.poll()
    if termination_reason == "signal":
        exit_code = 128 + int(forwarded_signal)
    elif termination_reason == "timeout":
        exit_code = 124
    elif termination_reason in {"orphaned_process_group", "supervisor_error"}:
        exit_code = 125
    else:
        exit_code = child_code if child_code is not None and child_code >= 0 else 1
    return {
        "exit_code": exit_code,
        "child_exit_code": child_code,
        "child_pid": process.pid,
        "child_process_group_id": process.pid,
        "termination_reason": termination_reason,
        "signal": int(forwarded_signal) if termination_reason == "signal" else None,
        "signal_grace_seconds": signal_grace,
        "escalated": escalated,
        "process_group_reaped": process_group_reaped,
        "supervisor_error_type": supervisor_error_type,
    }


def positive_seconds(value):
    parsed = float(value)
    if not math.isfinite(parsed) or parsed <= 0:
        raise argparse.ArgumentTypeError("must be a positive finite number")
    return parsed


def probe(command, timeout=15):
    try:
        completed = subprocess.run(
            command,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        return False, str(error)
    return completed.returncode == 0, completed.stdout.strip()


def check_health(spec):
    kind, separator, value = spec.partition(":")
    if not separator or not value:
        return {"spec": spec, "available": False, "detail": "expected kind:value"}
    if kind == "command":
        path = shutil.which(value)
        return {"spec": spec, "available": bool(path), "allocation": path or ""}
    if kind == "env":
        allocation = os.environ.get(value, "")
        return {"spec": spec, "available": bool(allocation), "allocation": allocation}
    if kind == "local":
        actual = platform.system().lower()
        expected = {"macos": "darwin"}.get(value.lower(), value.lower())
        return {"spec": spec, "available": actual == expected, "allocation": actual}
    if kind == "docker":
        ok, detail = probe(["docker", "info", "--format", "{{.ServerVersion}}"])
        return {"spec": spec, "available": ok, "allocation": value, "detail": detail[-1000:]}
    if kind == "ssh":
        ok, detail = probe(
            ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5", value, "exit 0"],
            timeout=10,
        )
        return {"spec": spec, "available": ok, "allocation": value, "detail": detail[-1000:]}
    if kind == "ios-simulator":
        if platform.system() != "Darwin" or not shutil.which("xcrun"):
            return {"spec": spec, "available": False, "detail": "xcrun requires macOS"}
        ok, output = probe(["xcrun", "simctl", "list", "devices", "available", "--json"])
        if not ok:
            return {"spec": spec, "available": False, "detail": output}
        try:
            devices = [
                device
                for runtime in json.loads(output).get("devices", {}).values()
                for device in runtime
                if device.get("isAvailable") and "iPhone" in device.get("name", "")
            ]
        except (TypeError, ValueError) as error:
            return {"spec": spec, "available": False, "detail": str(error)}
        matches = (
            sorted(devices, key=lambda item: item.get("state") != "Booted")
            if value == "auto"
            else [item for item in devices if value in (item.get("udid"), item.get("name"))]
        )
        if not matches:
            return {"spec": spec, "available": False, "detail": "simulator not found"}
        selected = matches[0]
        return {
            "spec": spec,
            "available": True,
            "allocation": selected.get("udid", ""),
            "name": selected.get("name", ""),
            "state": selected.get("state", ""),
        }
    if kind == "android":
        ok, output = probe(["adb", "devices"])
        if not ok:
            return {"spec": spec, "available": False, "detail": output}
        devices = [
            row.split()[0]
            for row in output.splitlines()[1:]
            if len(row.split()) >= 2 and row.split()[1] == "device"
        ]
        matches = devices if value == "auto" else [device for device in devices if device == value]
        return {
            "spec": spec,
            "available": bool(matches),
            "allocation": matches[0] if matches else "",
            "detail": "" if matches else "no authorized Android device",
        }
    if kind == "ios-device":
        if platform.system() != "Darwin" or not shutil.which("xcrun"):
            return {"spec": spec, "available": False, "detail": "devicectl requires macOS"}
        ok, output = probe(["xcrun", "devicectl", "list", "devices"], timeout=20)
        if not ok:
            return {"spec": spec, "available": False, "detail": output}
        devices = []
        for row in output.splitlines()[2:]:
            columns = [column.strip() for column in row.split("  ") if column.strip()]
            if len(columns) >= 4 and columns[3].startswith(("available", "connected")):
                devices.append({"name": columns[0], "identifier": columns[2]})
        matches = (
            devices
            if value == "auto"
            else [item for item in devices if value in (item["name"], item["identifier"])]
        )
        return {
            "spec": spec,
            "available": bool(matches),
            "allocation": matches[0]["identifier"] if matches else "",
            "name": matches[0]["name"] if matches else "",
            "detail": "" if matches else "no paired available iOS device",
        }
    return {"spec": spec, "available": False, "detail": "unknown health kind"}


def health_report(specs):
    return [check_health(spec) for spec in specs]


def state_root():
    configured = os.environ.get("IRIS_NATIVE_LAB_STATE_DIR") or os.environ.get(
        "NVPN_NATIVE_LAB_STATE_DIR"
    )
    return Path(configured) if configured else Path(tempfile.gettempdir()) / "iris-native-lab"


def lock_path(resource):
    digest = hashlib.sha256(resource.encode()).hexdigest()[:12]
    readable = "".join(char if char.isalnum() else "-" for char in resource)[:40]
    return state_root() / "locks" / f"{readable}-{digest}"


def sha256_file(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json_atomic(path, payload):
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
        fsync_directory(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


def fsync_directory(path):
    directory_descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(directory_descriptor)
    finally:
        os.close(directory_descriptor)


@contextlib.contextmanager
def recovery_mutex(subject_sha):
    """Serialize one recovery subject without making the mutex a reclaimable lock."""

    mutex_dir = state_root() / "recovery-mutexes"
    mutex_dir.mkdir(parents=True, exist_ok=True)
    mutex_path = mutex_dir / f"{subject_sha}.lock"
    flags = os.O_RDWR | os.O_CREAT
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(mutex_path, flags, 0o600)
    try:
        metadata = os.fstat(descriptor)
        pathname_metadata = mutex_path.lstat()
        if (
            fcntl is None
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or (metadata.st_mode & 0o777) != 0o600
            or metadata.st_dev != pathname_metadata.st_dev
            or metadata.st_ino != pathname_metadata.st_ino
        ):
            raise ValueError("recovery mutex must be a user-owned 0600 regular file")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        pathname_metadata = mutex_path.lstat()
        if (
            metadata.st_dev != pathname_metadata.st_dev
            or metadata.st_ino != pathname_metadata.st_ino
        ):
            raise ValueError("recovery mutex pathname changed while acquiring it")
        yield
    finally:
        if fcntl is not None:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            except OSError:
                pass
        os.close(descriptor)


def read_quarantine(path):
    quarantine_path = path / "quarantine.json"
    try:
        payload = json.loads(quarantine_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return payload if isinstance(payload, dict) else None


def alive(pid):
    try:
        os.kill(int(pid), 0)
        return int(pid) > 0
    except (OSError, TypeError, ValueError):
        return False


def acquire(resource, stale_after, owner_context=None):
    path = lock_path(resource)
    path.parent.mkdir(parents=True, exist_ok=True)
    owner_path = path / "owner.json"
    try:
        path.mkdir()
    except FileExistsError:
        try:
            owner = json.loads(owner_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            owner = {}
        quarantine = read_quarantine(path)
        local_dead = owner.get("host") == socket.gethostname() and not alive(owner.get("pid"))
        recovery_required = local_dead or not owner
        return None, {
            **owner,
            "resource": resource,
            "quarantined": quarantine is not None or owner.get("quarantined") is True,
            "recovery_required": recovery_required,
            "stale": time.time() - path.stat().st_mtime >= stale_after,
        }
    context = owner_context or {}
    owner = {
        "schemaVersion": 1,
        "artifactType": "native-lab managed lock owner",
        "resource": resource,
        "pid": os.getpid(),
        "host": socket.gethostname(),
        "startedAtEpoch": int(time.time()),
        "runId": context.get("run_id"),
        "primaryResource": context.get("primary_resource", resource),
        "lockedResources": [resource],
        "childPid": None,
        "childProcessGroupId": None,
        "state": "held",
    }
    try:
        write_json_atomic(owner_path, owner)
    except BaseException:
        shutil.rmtree(path, ignore_errors=True)
        raise
    return path, None


def health_resource(check):
    kind = str(check.get("spec", "")).partition(":")[0]
    allocation = str(check.get("allocation", ""))
    if not check.get("available") or kind not in RESERVED_KINDS or not allocation:
        return None
    if kind == "local":
        return f"host:local:{socket.gethostname()}"
    if kind == "ssh":
        return f"host:ssh:{allocation}"
    return f"{kind}:{allocation}"


def child_environment(checks, mappings):
    environment = os.environ.copy()
    for mapping in mappings:
        kind, separator, variable = mapping.partition("=")
        if not separator or not kind or not variable.isidentifier():
            raise ValueError(f"invalid allocation mapping: {mapping}")
        matches = [
            str(check.get("allocation"))
            for check in checks
            if str(check.get("spec", "")).partition(":")[0] == kind
            and check.get("available")
            and check.get("allocation")
        ]
        if len(matches) != 1:
            raise ValueError(f"allocation mapping {mapping} requires one available {kind}")
        environment[variable] = matches[0]
    return environment


def update_managed_lock_owners(locks, run_id, child=None):
    locked_resources = sorted(resource for _path, resource in locks)
    for path, resource in locks:
        owner_path = path / "owner.json"
        owner = regular_private_json(owner_path, "native-lab managed lock owner")
        if (
            owner.get("runId") != run_id
            or owner.get("pid") != os.getpid()
            or owner.get("resource") != resource
            or owner.get("state") != "held"
        ):
            raise RuntimeError("native-lab managed lock ownership changed")
        owner["lockedResources"] = locked_resources
        if child is not None:
            owner["childPid"] = child.pid
            owner["childProcessGroupId"] = child.pid
        write_json_atomic(owner_path, owner)


def write_report(report, destination=None):
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if destination:
        write_json_atomic(Path(destination), report)
    print(rendered, end="")


QUARANTINE_KEYS = {
    "schemaVersion",
    "artifactType",
    "quarantineId",
    "resource",
    "primaryResource",
    "lockedResources",
    "host",
    "lockOwnerPid",
    "childPid",
    "childProcessGroupId",
    "terminationReason",
    "signal",
    "signalGraceSeconds",
    "escalated",
    "processGroupReaped",
    "resultEvidence",
    "quarantinedAtEpoch",
}


def quarantine_common(payload):
    return {
        key: value
        for key, value in payload.items()
        if key not in {"schemaVersion", "artifactType", "quarantineId", "resource"}
    }


def quarantine_id(common):
    return hashlib.sha256(
        json.dumps(common, separators=(",", ":"), sort_keys=True).encode()
    ).hexdigest()


def quarantine_is_canonically_bound(payload):
    return (
        isinstance(payload, dict)
        and set(payload) == QUARANTINE_KEYS
        and payload.get("schemaVersion") == 1
        and payload.get("artifactType")
        == "native-lab unreaped process-group quarantine"
        and payload.get("quarantineId") == quarantine_id(quarantine_common(payload))
    )


def quarantine_locks(locks, primary_resource, outcome, report):
    locked_resources = sorted(resource for _path, resource in locks)
    quarantined_at = int(time.time())
    common = {
        "primaryResource": primary_resource,
        "lockedResources": locked_resources,
        "host": socket.gethostname(),
        "lockOwnerPid": os.getpid(),
        "childPid": outcome.get("child_pid"),
        "childProcessGroupId": outcome.get("child_process_group_id"),
        "terminationReason": outcome.get("termination_reason"),
        "signal": outcome.get("signal"),
        "signalGraceSeconds": outcome.get("signal_grace_seconds"),
        "escalated": outcome.get("escalated"),
        "processGroupReaped": False,
        "resultEvidence": {
            "status": report.get("status"),
            "category": report.get("category"),
            "exitCode": report.get("exit_code"),
            "childExitCode": report.get("child_exit_code"),
            "supervisorErrorType": report.get("supervisor_error_type"),
        },
        "quarantinedAtEpoch": quarantined_at,
    }
    quarantine_identifier = quarantine_id(common)
    for path, resource in locks:
        owner_path = path / "owner.json"
        try:
            owner = json.loads(owner_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            owner = {"resource": resource, "pid": os.getpid(), "host": socket.gethostname()}
        owner.update({"quarantined": True, "quarantine_id": quarantine_identifier})
        write_json_atomic(owner_path, owner)
    for path, resource in locks:
        payload = {
            "schemaVersion": 1,
            "artifactType": "native-lab unreaped process-group quarantine",
            "quarantineId": quarantine_identifier,
            "resource": resource,
            **common,
        }
        write_json_atomic(path / "quarantine.json", payload)


def regular_private_json(path, description):
    metadata = path.lstat()
    if (
        path.is_symlink()
        or not path.is_file()
        or metadata.st_size <= 0
        or metadata.st_uid != os.getuid()
        or (metadata.st_mode & 0o777) != 0o600
    ):
        raise ValueError(f"{description} must be a nonempty user-owned 0600 regular file")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"{description} must contain a JSON object")
    return payload


def read_lock_record(path):
    if not path.exists() and not path.is_symlink():
        return None, None
    metadata = path.lstat()
    if path.is_symlink() or not path.is_file() or metadata.st_size <= 0:
        raise ValueError(f"invalid native-lab lock record: {path}")
    raw = path.read_bytes()
    try:
        payload = json.loads(raw)
    except ValueError:
        payload = None
    return hashlib.sha256(raw).hexdigest(), payload


def recovery_subject(primary_resource):
    primary_path = lock_path(primary_resource)
    if primary_path.is_symlink() or not primary_path.is_dir():
        raise ValueError("primary recovery lock is missing or invalid")
    _primary_sha, primary_owner = read_lock_record(primary_path / "owner.json")
    run_id = primary_owner.get("runId") if isinstance(primary_owner, dict) else None
    owner_pid = primary_owner.get("pid") if isinstance(primary_owner, dict) else None
    owner_host = primary_owner.get("host") if isinstance(primary_owner, dict) else None
    paths = [primary_path]
    if isinstance(run_id, str) and run_id:
        for candidate in sorted((state_root() / "locks").iterdir()):
            if candidate == primary_path or candidate.is_symlink() or not candidate.is_dir():
                continue
            _candidate_sha, candidate_owner = read_lock_record(candidate / "owner.json")
            if (
                isinstance(candidate_owner, dict)
                and candidate_owner.get("runId") == run_id
                and candidate_owner.get("primaryResource") == primary_resource
                and candidate_owner.get("pid") == owner_pid
                and candidate_owner.get("host") == owner_host
            ):
                paths.append(candidate)
    records = []
    known_process_groups = set()
    for path in paths:
        lock_metadata = path.lstat()
        if path.is_symlink() or not stat.S_ISDIR(lock_metadata.st_mode):
            raise ValueError("recovery lock changed type while collecting evidence")
        owner_sha, owner = read_lock_record(path / "owner.json")
        resource = owner.get("resource") if isinstance(owner, dict) else primary_resource
        if not isinstance(resource, str) or not resource or lock_path(resource) != path:
            raise ValueError("lock owner resource binding is invalid")
        if isinstance(owner, dict):
            if owner.get("host") != socket.gethostname():
                raise ValueError("recovery requires the original lock-owner host")
            if alive(owner.get("pid")):
                raise ValueError("recovery refuses a live lock owner")
            pgid = owner.get("childProcessGroupId")
            if isinstance(pgid, int) and not isinstance(pgid, bool) and pgid > 0:
                known_process_groups.add(pgid)
        quarantine_sha, quarantine = read_lock_record(path / "quarantine.json")
        quarantine_valid = (
            quarantine_is_canonically_bound(quarantine)
            and quarantine.get("resource") == resource
            and quarantine.get("primaryResource") == primary_resource
        )
        if quarantine_valid:
            pgid = quarantine.get("childProcessGroupId")
            if isinstance(pgid, int) and not isinstance(pgid, bool) and pgid > 0:
                known_process_groups.add(pgid)
        final_metadata = path.lstat()
        if (
            lock_metadata.st_dev != final_metadata.st_dev
            or lock_metadata.st_ino != final_metadata.st_ino
        ):
            raise ValueError("recovery lock identity changed while collecting evidence")
        records.append(
            {
                "resource": resource,
                "lockDevice": lock_metadata.st_dev,
                "lockInode": lock_metadata.st_ino,
                "ownerReceiptSha256": owner_sha,
                "quarantineReceiptSha256": quarantine_sha,
                "quarantineIdValidated": bool(quarantine_valid),
            }
        )
    records.sort(key=lambda item: item["resource"])
    resources = [item["resource"] for item in records]
    if len(resources) != len(set(resources)) or primary_resource not in resources:
        raise ValueError("recovery resource set is invalid")
    verify_process_groups_absent(sorted(known_process_groups))
    subject = {
        "schemaVersion": 1,
        "artifactType": "native-lab recovery subject",
        "primaryResource": primary_resource,
        "lockedResources": resources,
        "ownerRunId": run_id,
        "lockRecords": records,
        "knownChildProcessGroupIds": sorted(known_process_groups),
    }
    subject_sha = hashlib.sha256(
        json.dumps(subject, separators=(",", ":"), sort_keys=True).encode()
    ).hexdigest()
    return subject, subject_sha


def verify_process_groups_absent(process_groups):
    for pgid in process_groups:
        if not isinstance(pgid, int) or isinstance(pgid, bool) or pgid <= 0:
            raise ValueError("known child process-group identifier is invalid")
        try:
            os.killpg(pgid, 0)
        except ProcessLookupError:
            continue
        except (PermissionError, OSError):
            raise RuntimeError("known child process group is not proven absent")
        raise RuntimeError("known child process group is still present")


def validate_recovery_evidence(evidence, primary_resource, subject, subject_sha):
    expected = {
        "schemaVersion": 1,
        "artifactType": "native-lab audited quarantine recovery",
        "primaryResource": primary_resource,
        "lockedResources": subject["lockedResources"],
        "recoverySubjectSha256": subject_sha,
        "auditedCleanupComplete": True,
        "knownProcessGroupsAbsentVerified": True,
        "unknownProcessGroupsAudited": True,
        "recoveryAuthorized": True,
    }
    if set(evidence) != set(expected) | {"auditedAtEpoch"} or any(
        evidence.get(key) != value for key, value in expected.items()
    ):
        raise ValueError("quarantine recovery evidence is stale or incomplete")
    audited_at = evidence.get("auditedAtEpoch")
    now = int(time.time())
    if (
        not isinstance(audited_at, int)
        or isinstance(audited_at, bool)
        or audited_at <= 0
        or audited_at > now + 30
        or now - audited_at > 1800
    ):
        raise ValueError("quarantine recovery audit timestamp is invalid")


def recovery_receipt(transaction):
    exit_code = 128 + transaction["deferredSignal"] if transaction["deferredSignal"] else 0
    return {
        "schemaVersion": 1,
        "artifactType": "native-lab quarantine recovery",
        "status": "recovered" if transaction["state"] == "recovered" else "authorized",
        "category": "audited_quarantine_recovery",
        "primaryResource": transaction["primaryResource"],
        "lockedResources": transaction["lockedResources"],
        "recoverySubjectSha256": transaction["recoverySubjectSha256"],
        "recoveryEvidenceSha256": transaction["recoveryEvidenceSha256"],
        "releasedResources": transaction["releasedResources"],
        "releasePendingResource": transaction["releasePendingResource"],
        "knownProcessGroupsAbsentVerified": True,
        "deferredSignal": transaction["deferredSignal"],
        "authorizedAtEpoch": transaction["authorizedAtEpoch"],
        "completedAtEpoch": transaction["completedAtEpoch"],
        "lastErrorType": transaction["lastErrorType"],
        "exit_code": exit_code,
    }


def write_recovery_journal(transaction_path, receipt_path, transaction):
    write_json_atomic(transaction_path, transaction)
    write_json_atomic(receipt_path, recovery_receipt(transaction))


def validate_recovery_transaction(transaction, primary_resource, subject_sha, evidence_sha):
    expected_keys = {
        "schemaVersion",
        "artifactType",
        "state",
        "primaryResource",
        "lockedResources",
        "ownerRunId",
        "lockRecords",
        "knownChildProcessGroupIds",
        "recoverySubjectSha256",
        "recoveryEvidenceSha256",
        "authorizedAtEpoch",
        "releasedResources",
        "releasePendingResource",
        "deferredSignal",
        "completedAtEpoch",
        "lastErrorType",
    }
    if (
        set(transaction) != expected_keys
        or transaction.get("schemaVersion") != 1
        or transaction.get("artifactType")
        != "native-lab quarantine recovery transaction"
        or transaction.get("primaryResource") != primary_resource
        or transaction.get("recoverySubjectSha256") != subject_sha
        or transaction.get("recoveryEvidenceSha256") != evidence_sha
        or transaction.get("state")
        not in {"authorized", "releasing", "blocked", "recovered"}
    ):
        raise ValueError("recovery transaction does not match this request")
    resources = transaction.get("lockedResources")
    records = transaction.get("lockRecords")
    released = transaction.get("releasedResources")
    if (
        not isinstance(resources, list)
        or resources != sorted(set(resources))
        or primary_resource not in resources
        or not isinstance(records, list)
        or any(
            not isinstance(record, dict)
            or set(record)
            != {
                "resource",
                "lockDevice",
                "lockInode",
                "ownerReceiptSha256",
                "quarantineReceiptSha256",
                "quarantineIdValidated",
            }
            for record in records
        )
        or [record.get("resource") for record in records] != resources
        or not isinstance(released, list)
        or released != sorted(set(released))
        or any(resource not in resources for resource in released)
    ):
        raise ValueError("recovery transaction resource state is invalid")
    for record in records:
        if (
            not isinstance(record["lockDevice"], int)
            or isinstance(record["lockDevice"], bool)
            or record["lockDevice"] < 0
            or not isinstance(record["lockInode"], int)
            or isinstance(record["lockInode"], bool)
            or record["lockInode"] <= 0
        ):
            raise ValueError("recovery transaction lock identity is invalid")
        for key in ("ownerReceiptSha256", "quarantineReceiptSha256"):
            value = record[key]
            if value is not None and (
                not isinstance(value, str)
                or len(value) != 64
                or any(character not in "0123456789abcdef" for character in value)
            ):
                raise ValueError("recovery transaction lock digest is invalid")
        if not isinstance(record["quarantineIdValidated"], bool):
            raise ValueError("recovery transaction quarantine binding is invalid")
    process_groups = transaction.get("knownChildProcessGroupIds")
    if (
        not isinstance(process_groups, list)
        or process_groups != sorted(set(process_groups))
    ):
        raise ValueError("recovery transaction process-group set is invalid")
    pending = transaction.get("releasePendingResource")
    if pending is not None and (pending not in resources or pending in released):
        raise ValueError("recovery transaction pending resource is invalid")
    subject = {
        "schemaVersion": 1,
        "artifactType": "native-lab recovery subject",
        "primaryResource": primary_resource,
        "lockedResources": resources,
        "ownerRunId": transaction.get("ownerRunId"),
        "lockRecords": records,
        "knownChildProcessGroupIds": process_groups,
    }
    recomputed = hashlib.sha256(
        json.dumps(subject, separators=(",", ":"), sort_keys=True).encode()
    ).hexdigest()
    if recomputed != subject_sha:
        raise ValueError("recovery transaction subject binding is invalid")
    if not isinstance(transaction.get("authorizedAtEpoch"), int):
        raise ValueError("recovery transaction authorization timestamp is invalid")
    if transaction.get("lastErrorType") is not None and not isinstance(
        transaction["lastErrorType"], str
    ):
        raise ValueError("recovery transaction error evidence is invalid")
    if transaction.get("state") == "recovered":
        if released != resources or not isinstance(transaction.get("completedAtEpoch"), int):
            raise ValueError("completed recovery transaction is incomplete")
    if transaction["state"] != "recovered":
        verify_process_groups_absent(process_groups)


def validate_recovery_output_paths(evidence_path, result_path, resources):
    evidence_resolved = evidence_path.resolve()
    result_resolved = result_path.resolve()
    for resource in resources:
        locked_path = lock_path(resource).resolve()
        for candidate, description in (
            (evidence_resolved, "evidence"),
            (result_resolved, "result"),
        ):
            try:
                candidate.relative_to(locked_path)
            except ValueError:
                continue
            raise ValueError(f"quarantine recovery {description} must survive outside locks")


def validate_recovery_lock(path, record):
    metadata = path.lstat()
    if (
        path.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_dev != record["lockDevice"]
        or metadata.st_ino != record["lockInode"]
    ):
        raise ValueError("lock identity changed after recovery authorization")
    owner_sha, _owner = read_lock_record(path / "owner.json")
    quarantine_sha, _quarantine = read_lock_record(path / "quarantine.json")
    final_metadata = path.lstat()
    if (
        metadata.st_dev != final_metadata.st_dev
        or metadata.st_ino != final_metadata.st_ino
        or owner_sha != record["ownerReceiptSha256"]
        or quarantine_sha != record["quarantineReceiptSha256"]
    ):
        raise ValueError("lock evidence changed after recovery authorization")
    return metadata


def claim_recovery_lock(path, claim_path, record, pending_from_prior_attempt):
    """Move the authorized inode away from the live lock namespace before deletion."""

    if claim_path.exists() or claim_path.is_symlink():
        validate_recovery_lock(claim_path, record)
        return claim_path
    if not path.exists() and not path.is_symlink():
        if pending_from_prior_attempt:
            return None
        raise ValueError("authorized lock disappeared before recovery release")
    try:
        metadata = validate_recovery_lock(path, record)
    except ValueError:
        if pending_from_prior_attempt:
            # A prior attempt can delete the authorized inode and then stop before
            # journaling it. Never mistake a replacement live lock for that inode.
            return None
        raise
    claim_path.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(claim_path.parent, 0o700)
    if claim_path.exists() or claim_path.is_symlink():
        raise ValueError("recovery claim path is unexpectedly occupied")
    os.rename(path, claim_path)
    fsync_directory(path.parent)
    fsync_directory(claim_path.parent)
    claimed_metadata = validate_recovery_lock(claim_path, record)
    if (
        claimed_metadata.st_dev != metadata.st_dev
        or claimed_metadata.st_ino != metadata.st_ino
    ):
        raise ValueError("recovery claimed a different lock inode")
    return claim_path


def recover_quarantine(args):
    if os.name != "posix":
        print("native-lab quarantine recovery requires POSIX process groups", file=sys.stderr)
        return 2
    evidence_path = Path(args.evidence)
    try:
        evidence = regular_private_json(evidence_path, "quarantine recovery evidence")
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"quarantine recovery preflight failed: {error}", file=sys.stderr)
        return 2
    requested_subject = evidence.get("recoverySubjectSha256")
    if (
        not isinstance(requested_subject, str)
        or len(requested_subject) != 64
        or any(character not in "0123456789abcdef" for character in requested_subject)
    ):
        print("quarantine recovery subject digest is invalid", file=sys.stderr)
        return 2
    journal_dir = state_root() / "recoveries" / requested_subject
    transaction_path = journal_dir / "transaction.json"
    receipt_path = journal_dir / "receipt.json"
    evidence_sha = sha256_file(evidence_path)
    result_path = Path(args.result)
    with DeferredSignals() as deferred:
        try:
            with recovery_mutex(requested_subject):
                if transaction_path.exists() or transaction_path.is_symlink():
                    transaction = regular_private_json(
                        transaction_path, "native-lab recovery transaction"
                    )
                    validate_recovery_transaction(
                        transaction, args.resource, requested_subject, evidence_sha
                    )
                    write_recovery_journal(transaction_path, receipt_path, transaction)
                else:
                    subject, observed_subject = recovery_subject(args.resource)
                    if observed_subject != requested_subject:
                        raise ValueError("recovery subject changed before authorization")
                    validate_recovery_evidence(
                        evidence, args.resource, subject, observed_subject
                    )
                    if deferred.received is not None:
                        return 128 + int(deferred.received)
                    now = int(time.time())
                    transaction = {
                        "schemaVersion": 1,
                        "artifactType": "native-lab quarantine recovery transaction",
                        "state": "authorized",
                        "primaryResource": args.resource,
                        "lockedResources": subject["lockedResources"],
                        "ownerRunId": subject["ownerRunId"],
                        "lockRecords": subject["lockRecords"],
                        "knownChildProcessGroupIds": subject["knownChildProcessGroupIds"],
                        "recoverySubjectSha256": observed_subject,
                        "recoveryEvidenceSha256": evidence_sha,
                        "authorizedAtEpoch": now,
                        "releasedResources": [],
                        "releasePendingResource": None,
                        "deferredSignal": None,
                        "completedAtEpoch": None,
                        "lastErrorType": None,
                    }
                    journal_dir.mkdir(parents=True, exist_ok=True)
                    for residue in journal_dir.iterdir():
                        if not (
                            residue.is_file()
                            and not residue.is_symlink()
                            and residue.name.startswith((".transaction.json.", ".receipt.json."))
                        ):
                            raise ValueError("incomplete recovery journal requires manual audit")
                        residue.unlink()
                    write_recovery_journal(transaction_path, receipt_path, transaction)
                expected_resources = transaction["lockedResources"]
                released = transaction["releasedResources"]
                validate_recovery_output_paths(evidence_path, result_path, expected_resources)
                if (
                    not isinstance(expected_resources, list)
                    or expected_resources != sorted(set(expected_resources))
                    or not isinstance(released, list)
                    or any(resource not in expected_resources for resource in released)
                ):
                    raise ValueError("recovery transaction resource state is invalid")
                if transaction["state"] != "recovered":
                    for record in transaction["lockRecords"]:
                        resource = record["resource"]
                        if resource in released:
                            continue
                        pending_from_prior_attempt = (
                            transaction["releasePendingResource"] == resource
                        )
                        if deferred.received is not None and transaction["deferredSignal"] is None:
                            transaction["deferredSignal"] = int(deferred.received)
                        transaction["state"] = "releasing"
                        transaction["lastErrorType"] = None
                        transaction["releasePendingResource"] = resource
                        write_recovery_journal(transaction_path, receipt_path, transaction)
                        path = lock_path(resource)
                        claim_path = journal_dir / "claimed-locks" / path.name
                        claimed = claim_recovery_lock(
                            path, claim_path, record, pending_from_prior_attempt
                        )
                        if claimed is not None:
                            # Revalidate the claimed inode and record hashes immediately
                            # before deletion; a fresh run can now safely own `path`.
                            validate_recovery_lock(claimed, record)
                            shutil.rmtree(claimed)
                            fsync_directory(claimed.parent)
                        released.append(resource)
                        released.sort()
                        transaction["releasedResources"] = released
                        transaction["releasePendingResource"] = None
                        write_recovery_journal(transaction_path, receipt_path, transaction)
                    transaction["state"] = "recovered"
                    transaction["lastErrorType"] = None
                    transaction["completedAtEpoch"] = int(time.time())
                    if deferred.received is not None and transaction["deferredSignal"] is None:
                        transaction["deferredSignal"] = int(deferred.received)
                    write_recovery_journal(transaction_path, receipt_path, transaction)
                receipt = recovery_receipt(transaction)
                if result_path.exists() or result_path.is_symlink():
                    observed = regular_private_json(result_path, "quarantine recovery result")
                    if observed != receipt:
                        raise ValueError(
                            "quarantine recovery result path contains different evidence"
                        )
                else:
                    write_json_atomic(result_path, receipt)
                print(json.dumps(receipt, indent=2, sort_keys=True))
                return receipt["exit_code"]
        except (OSError, ValueError, KeyError, TypeError, RuntimeError) as error:
            try:
                with recovery_mutex(requested_subject):
                    if transaction_path.exists() or transaction_path.is_symlink():
                        durable_transaction = regular_private_json(
                            transaction_path, "native-lab recovery transaction"
                        )
                        validate_recovery_transaction(
                            durable_transaction,
                            args.resource,
                            requested_subject,
                            evidence_sha,
                        )
                        if durable_transaction["state"] != "recovered":
                            if (
                                deferred.received is not None
                                and durable_transaction.get("deferredSignal") is None
                            ):
                                durable_transaction["deferredSignal"] = int(
                                    deferred.received
                                )
                            durable_transaction["state"] = "blocked"
                            durable_transaction["lastErrorType"] = type(error).__name__
                            write_recovery_journal(
                                transaction_path, receipt_path, durable_transaction
                            )
            except (OSError, ValueError, KeyError, TypeError, RuntimeError) as journal_error:
                print(
                    "quarantine recovery error could not be added to its durable journal: "
                    f"{journal_error}",
                    file=sys.stderr,
                )
            print(f"quarantine recovery blocked: {error}", file=sys.stderr)
            return INFRASTRUCTURE_UNAVAILABLE


def run_managed(args):
    if os.name != "posix":
        write_report(
            {
                "status": "product_failure",
                "category": "configuration",
                "detail": "signal-safe native-lab managed runs require POSIX process groups",
                "exit_code": 2,
            },
            args.result,
        )
        return 2
    started = time.monotonic()
    run_id = hashlib.sha256(
        f"{socket.gethostname()}:{os.getpid()}:{time.time_ns()}:{args.resource}".encode()
    ).hexdigest()
    owner_context = {"run_id": run_id, "primary_resource": args.resource}
    locks = []
    resources = []
    quarantined = False

    def cancelled_outcome(deferred):
        return {
            "exit_code": 128 + int(deferred.received),
            "child_exit_code": None,
            "child_pid": None,
            "child_process_group_id": None,
            "termination_reason": "signal",
            "signal": int(deferred.received),
            "signal_grace_seconds": args.signal_grace,
            "escalated": False,
            "process_group_reaped": True,
            "supervisor_error_type": None,
        }

    with DeferredSignals() as deferred:
        try:
            primary, owner = acquire(args.resource, args.stale_after, owner_context)
            if primary is None:
                write_report(
                    {
                        "status": "infrastructure_unavailable",
                        "category": "resource_busy",
                        "resource": args.resource,
                        "owner": owner or {},
                        "exit_code": INFRASTRUCTURE_UNAVAILABLE,
                    },
                    args.result,
                )
                return INFRASTRUCTURE_UNAVAILABLE
            locks.append((primary, args.resource))
            checks = health_report(args.health)
            if deferred.received is not None:
                outcome = cancelled_outcome(deferred)
            else:
                outcome = None
            if outcome is None and any(not check["available"] for check in checks):
                write_report(
                    {
                        "status": "infrastructure_unavailable",
                        "category": "preflight",
                        "resource": args.resource,
                        "health": checks,
                        "exit_code": INFRASTRUCTURE_UNAVAILABLE,
                    },
                    args.result,
                )
                return INFRASTRUCTURE_UNAVAILABLE
            if outcome is None:
                resources = sorted({item for check in checks if (item := health_resource(check))})
                for resource in resources:
                    lock, owner = acquire(resource, args.stale_after, owner_context)
                    if deferred.received is not None:
                        if lock is not None:
                            locks.append((lock, resource))
                        outcome = cancelled_outcome(deferred)
                        break
                    if lock is None:
                        write_report(
                            {
                                "status": "infrastructure_unavailable",
                                "category": "resource_busy",
                                "resource": args.resource,
                                "busy_resource": resource,
                                "owner": owner or {},
                                "exit_code": INFRASTRUCTURE_UNAVAILABLE,
                            },
                            args.result,
                        )
                        return INFRASTRUCTURE_UNAVAILABLE
                    locks.append((lock, resource))
            if outcome is None:
                try:
                    environment = child_environment(checks, args.allocation_env)
                except ValueError as error:
                    if deferred.received is not None:
                        outcome = cancelled_outcome(deferred)
                    else:
                        write_report(
                            {
                                "status": "product_failure",
                                "category": "configuration",
                                "detail": str(error),
                                "exit_code": 2,
                            },
                            args.result,
                        )
                        return 2
            if outcome is None:
                update_managed_lock_owners(locks, run_id)
                if deferred.received is not None:
                    outcome = cancelled_outcome(deferred)
                else:
                    outcome = wait_for_managed_child(
                        args.command[1:],
                        environment,
                        args.timeout,
                        args.signal_grace,
                        deferred,
                        lambda child: update_managed_lock_owners(locks, run_id, child),
                    )
            code = outcome["exit_code"]
            if outcome["termination_reason"] == "signal":
                status, category = "cancelled", "signal"
            elif outcome["termination_reason"] == "timeout":
                status, category = "product_failure", "verification_timeout"
            elif outcome["termination_reason"] == "orphaned_process_group":
                status, category = "product_failure", "process_group_leak"
            elif outcome["termination_reason"] == "supervisor_error":
                status, category = "product_failure", "process_supervisor"
            else:
                status = (
                    "passed"
                    if code == 0
                    else "infrastructure_unavailable"
                    if code == 75
                    else "product_failure"
                )
                category = "test_environment" if code == 75 else "verification"
            report = {
                "status": status,
                "category": category,
                "resource": args.resource,
                "reserved_resources": sorted(
                    resource for _path, resource in locks if resource != args.resource
                ),
                "duration_seconds": round(time.monotonic() - started, 3),
                "exit_code": code,
                "child_exit_code": outcome["child_exit_code"],
                "child_pid": outcome["child_pid"],
                "child_process_group_id": outcome["child_process_group_id"],
                "termination_reason": outcome["termination_reason"],
                "signal_grace_seconds": outcome["signal_grace_seconds"],
                "escalated": outcome["escalated"],
                "process_group_reaped": outcome["process_group_reaped"],
                "supervisor_error_type": outcome["supervisor_error_type"],
            }
            if outcome["signal"] is not None:
                report["signal"] = outcome["signal"]
            if outcome["process_group_reaped"] is not True:
                quarantined = True
                quarantine_locks(locks, args.resource, outcome, report)
            write_report(
                report,
                args.result,
            )
            return code
        finally:
            if not quarantined:
                for lock, _resource in reversed(locks):
                    shutil.rmtree(lock, ignore_errors=True)


def parser():
    root = argparse.ArgumentParser(description=__doc__)
    commands = root.add_subparsers(dest="subcommand", required=True)
    health = commands.add_parser("health")
    health.add_argument("--health", action="append", required=True)
    health.add_argument("--result")
    run = commands.add_parser("run")
    run.add_argument("--resource", required=True)
    run.add_argument("--health", action="append", default=[])
    run.add_argument("--allocation-env", action="append", default=[])
    run.add_argument("--result")
    run.add_argument("--timeout", type=int, default=0)
    run.add_argument(
        "--signal-grace",
        type=positive_seconds,
        default=DEFAULT_SIGNAL_GRACE_SECONDS,
        help="seconds to preserve child cleanup after TERM/HUP/INT before escalation",
    )
    run.add_argument("--stale-after", type=int, default=21600)
    run.add_argument("command", nargs=argparse.REMAINDER)
    recover = commands.add_parser(
        "recover-quarantine",
        help="release a durable quarantine after separate audited cleanup evidence",
    )
    recover.add_argument("--resource", required=True)
    recover.add_argument("--evidence", required=True)
    recover.add_argument("--result", required=True)
    return root


def main():
    args = parser().parse_args()
    if args.subcommand == "health":
        checks = health_report(args.health)
        available = all(check["available"] for check in checks)
        write_report(
            {
                "status": "available" if available else "infrastructure_unavailable",
                "category": "preflight",
                "health": checks,
                "exit_code": 0 if available else INFRASTRUCTURE_UNAVAILABLE,
            },
            args.result,
        )
        return 0 if available else INFRASTRUCTURE_UNAVAILABLE
    if args.subcommand == "recover-quarantine":
        return recover_quarantine(args)
    if not args.command or args.command[0] != "--" or len(args.command) == 1:
        print("run requires -- <command>", file=sys.stderr)
        return 2
    return run_managed(args)


if __name__ == "__main__":
    raise SystemExit(main())
