#!/usr/bin/env python3

import argparse
import contextlib
import hashlib
import importlib.util
import io
import json
import os
import platform
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock


LAB = Path(__file__).resolve().with_name("native-lab.py")
LAB_SPEC = importlib.util.spec_from_file_location("native_lab", LAB)
NATIVE_LAB = importlib.util.module_from_spec(LAB_SPEC)
LAB_SPEC.loader.exec_module(NATIVE_LAB)


class NativeLabTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.state_dir = str(Path(self.temp.name) / "state")
        previous_state = os.environ.get("NVPN_NATIVE_LAB_STATE_DIR")
        os.environ["NVPN_NATIVE_LAB_STATE_DIR"] = self.state_dir
        self.addCleanup(
            lambda: os.environ.pop("NVPN_NATIVE_LAB_STATE_DIR", None)
            if previous_state is None
            else os.environ.__setitem__("NVPN_NATIVE_LAB_STATE_DIR", previous_state)
        )

    def run_lab(self, *args: str) -> subprocess.CompletedProcess:
        environment = os.environ.copy()
        environment["NVPN_NATIVE_LAB_STATE_DIR"] = self.state_dir
        return subprocess.run(
            [sys.executable, str(LAB), *args],
            check=False,
            capture_output=True,
            text=True,
            env=environment,
        )

    def start_lab(self, *args: str) -> subprocess.Popen:
        environment = os.environ.copy()
        environment["NVPN_NATIVE_LAB_STATE_DIR"] = self.state_dir
        return subprocess.Popen(
            [sys.executable, str(LAB), *args],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=environment,
            start_new_session=True,
        )

    def wait_for_path(self, path: Path, timeout: float = 5.0) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if path.exists():
                return
            time.sleep(0.01)
        self.fail(f"timed out waiting for {path}")

    def resource_lock(self, resource: str) -> Path:
        digest = hashlib.sha256(resource.encode()).hexdigest()[:12]
        readable = "".join(char if char.isalnum() else "-" for char in resource)[:40]
        return Path(self.state_dir) / "locks" / f"{readable}-{digest}"

    def write_recovery_evidence(
        self, resource: str, subject: dict, subject_sha: str, name: str
    ) -> Path:
        evidence = Path(self.temp.name) / name
        evidence.write_text(
            json.dumps(
                {
                    "schemaVersion": 1,
                    "artifactType": "native-lab audited quarantine recovery",
                    "primaryResource": resource,
                    "lockedResources": subject["lockedResources"],
                    "recoverySubjectSha256": subject_sha,
                    "auditedCleanupComplete": True,
                    "knownProcessGroupsAbsentVerified": True,
                    "unknownProcessGroupsAudited": True,
                    "recoveryAuthorized": True,
                    "auditedAtEpoch": int(time.time()),
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        evidence.chmod(0o600)
        return evidence

    def stop_process(self, process: subprocess.Popen, child_pid: Path = None) -> None:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)
        if child_pid is not None and child_pid.exists():
            try:
                os.killpg(int(child_pid.read_text(encoding="utf-8")), signal.SIGKILL)
            except (ProcessLookupError, ValueError):
                pass
        process.communicate(timeout=5)

    def test_ios_health_accepts_connected_selected_device(self) -> None:
        inventory = (
            "Name  Hostname  Identifier  State  Model\n"
            "----  --------  ----------  -----  -----\n"
            "Selected phone  selected.local  selected-id  connected  iPhone\n"
            "Other phone  other.local  other-id  available (paired)  iPhone\n"
            "Offline phone  offline.local  offline-id  unavailable  iPhone\n"
        )
        with (
            mock.patch.object(NATIVE_LAB.platform, "system", return_value="Darwin"),
            mock.patch.object(NATIVE_LAB.shutil, "which", return_value="/usr/bin/xcrun"),
            mock.patch.object(NATIVE_LAB, "probe", return_value=(True, inventory)),
        ):
            for selected in ("Selected phone", "selected-id", "Other phone", "offline-id", "missing"):
                with self.subTest(selected=selected):
                    result = NATIVE_LAB.check_health(f"ios-device:{selected}")
                    expected = "selected-id" if selected in ("Selected phone", "selected-id") else (
                        "other-id" if selected == "Other phone" else ""
                    )
                    self.assertEqual(result["available"], bool(expected))
                    self.assertEqual(result["allocation"], expected)

    def test_health_distinguishes_available_and_missing_commands(self) -> None:
        available = self.run_lab("health", "--health", f"command:{Path(sys.executable).name}")
        self.assertEqual(available.returncode, 0, available.stderr)
        self.assertEqual(json.loads(available.stdout)["status"], "available")
        missing = self.run_lab("health", "--health", "command:not-a-real-native-lab-tool")
        self.assertEqual(missing.returncode, 75)

    @unittest.skipIf(os.name != "posix", "managed runs require POSIX process groups")
    def test_run_classifies_product_and_infrastructure_failures(self) -> None:
        product = self.run_lab(
            "run", "--resource", "matrix", "--", sys.executable, "-c", "raise SystemExit(7)"
        )
        self.assertEqual(product.returncode, 7)
        self.assertEqual(json.loads(product.stdout)["status"], "product_failure")
        infrastructure = self.run_lab(
            "run", "--resource", "matrix", "--", sys.executable, "-c", "raise SystemExit(75)"
        )
        self.assertEqual(infrastructure.returncode, 75)
        self.assertEqual(json.loads(infrastructure.stdout)["status"], "infrastructure_unavailable")

    @unittest.skipIf(os.name != "posix", "managed runs require POSIX process groups")
    def test_run_exports_the_selected_allocation(self) -> None:
        variable = "NVPN_NATIVE_LAB_TEST_DEVICE"
        previous = os.environ.get(variable)
        os.environ[variable] = "known-device"
        self.addCleanup(
            lambda: os.environ.pop(variable, None)
            if previous is None
            else os.environ.__setitem__(variable, previous)
        )
        completed = self.run_lab(
            "run",
            "--resource",
            "matrix",
            "--health",
            f"env:{variable}",
            "--allocation-env",
            "env=ALLOCATED_DEVICE",
            "--",
            sys.executable,
            "-c",
            "import os; raise SystemExit(0 if os.environ.get('ALLOCATED_DEVICE') == 'known-device' else 9)",
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

    @unittest.skipIf(os.name != "posix", "managed runs require POSIX process groups")
    def test_run_rejects_a_busy_named_host(self) -> None:
        system = platform.system().lower()
        label = {"darwin": "macos", "windows": "windows", "linux": "linux"}[system]
        resource = f"host:local:{socket.gethostname()}"
        digest = hashlib.sha256(resource.encode()).hexdigest()[:12]
        readable = "".join(char if char.isalnum() else "-" for char in resource)[:40]
        lock = Path(self.state_dir) / "locks" / f"{readable}-{digest}"
        lock.mkdir(parents=True)
        (lock / "owner.json").write_text(
            json.dumps({"resource": resource, "pid": os.getpid(), "host": socket.gethostname()}),
            encoding="utf-8",
        )
        completed = self.run_lab(
            "run",
            "--resource",
            "other-matrix",
            "--health",
            f"local:{label}",
            "--",
            sys.executable,
            "-c",
            "raise SystemExit(0)",
        )
        report = json.loads(completed.stdout)
        self.assertEqual(completed.returncode, 75)
        self.assertEqual(report["busy_resource"], resource)

    @unittest.skipIf(os.name != "posix", "POSIX process-group signal contract")
    def test_signal_keeps_lock_owned_until_child_cleanup_finishes(self) -> None:
        resource = "physical-ios-release"
        lock = self.resource_lock(resource)
        ready = Path(self.temp.name) / "child-ready"
        cleanup_started = Path(self.temp.name) / "cleanup-started"
        allow_cleanup = Path(self.temp.name) / "allow-cleanup"
        cleanup_finished = Path(self.temp.name) / "cleanup-finished"
        child_pid = Path(self.temp.name) / "child-pid"
        result = Path(self.temp.name) / "result.json"
        child = Path(self.temp.name) / "signal-cleanup-child.py"
        child.write_text(
            """\
import os
import signal
import sys
import time
from pathlib import Path

ready, cleanup_started, allow_cleanup, cleanup_finished, child_pid = map(Path, sys.argv[1:])
pending = []
for watched in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
    signal.signal(watched, lambda signum, _frame: pending.append(signum))
child_pid.write_text(str(os.getpid()), encoding="utf-8")
ready.write_text("ready\\n", encoding="utf-8")
while not pending:
    time.sleep(0.01)
cleanup_started.write_text(f"{pending[0]}\\n", encoding="utf-8")
while not allow_cleanup.exists():
    time.sleep(0.01)
cleanup_finished.write_text("finished\\n", encoding="utf-8")
raise SystemExit(128 + pending[0])
""",
            encoding="utf-8",
        )
        lab = self.start_lab(
            "run",
            "--resource",
            resource,
            "--signal-grace",
            "10",
            "--result",
            str(result),
            "--",
            sys.executable,
            str(child),
            str(ready),
            str(cleanup_started),
            str(allow_cleanup),
            str(cleanup_finished),
            str(child_pid),
        )
        self.addCleanup(self.stop_process, lab, child_pid)
        self.wait_for_path(ready)
        self.wait_for_path(lock / "owner.json")

        os.killpg(lab.pid, signal.SIGTERM)
        self.wait_for_path(cleanup_started)

        owner = json.loads((lock / "owner.json").read_text(encoding="utf-8"))
        self.assertEqual(owner["pid"], lab.pid)
        self.assertIsNone(lab.poll(), "native-lab exited while child cleanup was active")
        competing = self.run_lab(
            "run",
            "--resource",
            resource,
            "--",
            sys.executable,
            "-c",
            "raise SystemExit(0)",
        )
        self.assertEqual(competing.returncode, 75, competing.stderr)
        self.assertEqual(json.loads(competing.stdout)["category"], "resource_busy")

        allow_cleanup.write_text("continue\n", encoding="utf-8")
        stdout, stderr = lab.communicate(timeout=5)
        self.assertEqual(lab.returncode, 128 + signal.SIGTERM, stderr)
        self.assertTrue(cleanup_finished.exists())
        self.assertFalse(lock.exists())
        report = json.loads(result.read_text(encoding="utf-8"))
        self.assertEqual(report["status"], "cancelled")
        self.assertEqual(report["category"], "signal")
        self.assertEqual(report["signal"], signal.SIGTERM)
        self.assertFalse(report["escalated"])
        self.assertTrue(report["process_group_reaped"])
        self.assertEqual(json.loads(stdout), report)
        with self.assertRaises(ProcessLookupError):
            os.kill(int(child_pid.read_text(encoding="utf-8")), 0)

        subsequent = self.run_lab(
            "run",
            "--resource",
            resource,
            "--",
            sys.executable,
            "-c",
            "raise SystemExit(0)",
        )
        self.assertEqual(subsequent.returncode, 0, subsequent.stderr)

    @unittest.skipIf(os.name != "posix", "POSIX process-group signal contract")
    def test_signal_escalates_only_after_bounded_cleanup_grace(self) -> None:
        resource = "uncooperative-ios-release"
        lock = self.resource_lock(resource)
        ready = Path(self.temp.name) / "uncooperative-ready"
        result = Path(self.temp.name) / "uncooperative-result.json"
        child_pid = Path(self.temp.name) / "uncooperative-child-pid"
        child = Path(self.temp.name) / "uncooperative-child.py"
        child.write_text(
            """\
import os
import signal
import sys
import time
from pathlib import Path

ready, child_pid = map(Path, sys.argv[1:])
for watched in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
    signal.signal(watched, lambda _signum, _frame: None)
child_pid.write_text(str(os.getpid()), encoding="utf-8")
ready.write_text("ready\\n", encoding="utf-8")
while True:
    time.sleep(0.1)
""",
            encoding="utf-8",
        )
        grace = 0.4
        lab = self.start_lab(
            "run",
            "--resource",
            resource,
            "--signal-grace",
            str(grace),
            "--result",
            str(result),
            "--",
            sys.executable,
            str(child),
            str(ready),
            str(child_pid),
        )
        self.addCleanup(self.stop_process, lab, child_pid)
        self.wait_for_path(ready)
        self.wait_for_path(lock / "owner.json")
        started = time.monotonic()
        os.killpg(lab.pid, signal.SIGTERM)
        _stdout, stderr = lab.communicate(timeout=5)
        elapsed = time.monotonic() - started

        self.assertEqual(lab.returncode, 128 + signal.SIGTERM, stderr)
        self.assertGreaterEqual(elapsed, grace * 0.8)
        report = json.loads(result.read_text(encoding="utf-8"))
        self.assertTrue(report["escalated"])
        self.assertEqual(report["signal_grace_seconds"], grace)
        self.assertTrue(report["process_group_reaped"])
        self.assertFalse(lock.exists())
        with self.assertRaises(ProcessLookupError):
            os.kill(int(child_pid.read_text(encoding="utf-8")), 0)

    @unittest.skipIf(os.name != "posix", "POSIX process-group signal contract")
    def test_normal_leader_exit_reaps_lingering_process_group_before_unlock(self) -> None:
        resource = "normal-exit-with-descendant"
        descendant_pid = Path(self.temp.name) / "descendant-pid"
        result = Path(self.temp.name) / "orphan-result.json"
        child = Path(self.temp.name) / "orphaning-child.py"
        child.write_text(
            """\
import subprocess
import sys
from pathlib import Path

output = Path(sys.argv[1])
descendant = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
output.write_text(str(descendant.pid), encoding="utf-8")
""",
            encoding="utf-8",
        )
        completed = self.run_lab(
            "run",
            "--resource",
            resource,
            "--signal-grace",
            "1",
            "--result",
            str(result),
            "--",
            sys.executable,
            str(child),
            str(descendant_pid),
        )
        report = json.loads(result.read_text(encoding="utf-8"))
        self.assertEqual(completed.returncode, 125, completed.stderr)
        self.assertEqual(report["category"], "process_group_leak")
        self.assertTrue(report["process_group_reaped"])
        self.assertFalse(self.resource_lock(resource).exists())
        with self.assertRaises(ProcessLookupError):
            os.kill(int(descendant_pid.read_text(encoding="utf-8")), 0)

    @unittest.skipIf(os.name != "posix", "POSIX process-group signal contract")
    def test_timeout_preserves_cooperative_cleanup_then_reaps_and_unlocks(self) -> None:
        resource = "timeout-cleanup"
        ready = Path(self.temp.name) / "timeout-ready"
        cleanup_finished = Path(self.temp.name) / "timeout-cleanup-finished"
        result = Path(self.temp.name) / "timeout-result.json"
        child = Path(self.temp.name) / "timeout-child.py"
        child.write_text(
            """\
import signal
import sys
import time
from pathlib import Path

ready, finished = map(Path, sys.argv[1:])
pending = []
signal.signal(signal.SIGTERM, lambda signum, _frame: pending.append(signum))
ready.write_text("ready\\n", encoding="utf-8")
while not pending:
    time.sleep(0.01)
time.sleep(0.2)
finished.write_text("finished\\n", encoding="utf-8")
raise SystemExit(128 + pending[0])
""",
            encoding="utf-8",
        )
        started = time.monotonic()
        completed = self.run_lab(
            "run",
            "--resource",
            resource,
            "--timeout",
            "1",
            "--signal-grace",
            "2",
            "--result",
            str(result),
            "--",
            sys.executable,
            str(child),
            str(ready),
            str(cleanup_finished),
        )
        elapsed = time.monotonic() - started
        report = json.loads(result.read_text(encoding="utf-8"))
        self.assertEqual(completed.returncode, 124, completed.stderr)
        self.assertGreaterEqual(elapsed, 1)
        self.assertLess(elapsed, 3)
        self.assertTrue(cleanup_finished.exists())
        self.assertEqual(report["category"], "verification_timeout")
        self.assertTrue(report["process_group_reaped"])
        self.assertFalse(self.resource_lock(resource).exists())

    @unittest.skipIf(os.name != "posix", "POSIX process-group signal contract")
    def test_supervisor_exception_still_terminates_and_reaps_child_group(self) -> None:
        ready = Path(self.temp.name) / "exception-ready"
        child_pid = Path(self.temp.name) / "exception-child-pid"
        child = Path(self.temp.name) / "exception-child.py"
        child.write_text(
            """\
import os
import sys
import time
from pathlib import Path

ready, child_pid = map(Path, sys.argv[1:])
child_pid.write_text(str(os.getpid()), encoding="utf-8")
ready.write_text("ready\\n", encoding="utf-8")
while True:
    time.sleep(0.1)
""",
            encoding="utf-8",
        )
        deferred = argparse.Namespace(received=signal.SIGTERM)
        real_signal_group = NATIVE_LAB.signal_process_group
        calls = 0

        def fail_once(process, signum):
            nonlocal calls
            calls += 1
            if calls == 1:
                self.wait_for_path(ready)
                raise RuntimeError("injected supervisor failure")
            return real_signal_group(process, signum)

        with mock.patch.object(NATIVE_LAB, "signal_process_group", side_effect=fail_once):
            outcome = NATIVE_LAB.wait_for_managed_child(
                [sys.executable, str(child), str(ready), str(child_pid)],
                os.environ.copy(),
                timeout=0,
                signal_grace=1,
                deferred=deferred,
            )
        self.assertEqual(outcome["termination_reason"], "supervisor_error")
        self.assertEqual(outcome["supervisor_error_type"], "RuntimeError")
        self.assertTrue(outcome["process_group_reaped"])
        with self.assertRaises(ProcessLookupError):
            os.kill(int(child_pid.read_text(encoding="utf-8")), 0)

    @unittest.skipIf(os.name != "posix", "POSIX signal precedence contract")
    def test_signal_during_unavailable_health_preflight_wins_over_exit_75(self) -> None:
        resource = "signal-during-health"
        result = Path(self.temp.name) / "preflight-signal-result.json"
        args = argparse.Namespace(
            resource=resource,
            stale_after=21600,
            health=["command:unused"],
            allocation_env=[],
            command=["--", sys.executable, "-c", "raise SystemExit(0)"],
            timeout=0,
            signal_grace=1,
            result=str(result),
        )

        def interrupted_health(_specs):
            os.kill(os.getpid(), signal.SIGTERM)
            return [{"spec": "command:unused", "available": False, "detail": "interrupted"}]

        output = io.StringIO()
        with mock.patch.object(NATIVE_LAB, "health_report", side_effect=interrupted_health):
            with contextlib.redirect_stdout(output):
                code = NATIVE_LAB.run_managed(args)
        report = json.loads(result.read_text(encoding="utf-8"))
        self.assertEqual(code, 128 + signal.SIGTERM)
        self.assertEqual(report["status"], "cancelled")
        self.assertEqual(report["category"], "signal")
        self.assertTrue(report["process_group_reaped"])
        self.assertFalse(self.resource_lock(resource).exists())
        self.assertEqual(json.loads(output.getvalue()), report)

    @unittest.skipIf(os.name != "posix", "POSIX quarantine contract")
    def test_dead_owner_quarantine_is_not_reclaimed_and_requires_audited_recovery(self) -> None:
        resource = "quarantined-physical-device"
        lock, owner = NATIVE_LAB.acquire(resource, stale_after=0)
        self.assertIsNotNone(lock, owner)
        outcome = {
            "child_pid": 987654321,
            "child_process_group_id": 987654321,
            "termination_reason": "supervisor_error",
            "signal": None,
            "signal_grace_seconds": 1,
            "escalated": True,
            "process_group_reaped": False,
        }
        report = {
            "status": "product_failure",
            "category": "process_supervisor",
            "exit_code": 125,
            "child_exit_code": None,
            "supervisor_error_type": "OSError",
        }
        NATIVE_LAB.quarantine_locks([(lock, resource)], resource, outcome, report)
        owner_path = lock / "owner.json"
        quarantine_path = lock / "quarantine.json"
        dead_owner = json.loads(owner_path.read_text(encoding="utf-8"))
        dead_owner["pid"] = 2**31 - 1
        quarantine = json.loads(quarantine_path.read_text(encoding="utf-8"))
        quarantine["lockOwnerPid"] = dead_owner["pid"]
        common = {
            key: value
            for key, value in quarantine.items()
            if key not in {"schemaVersion", "artifactType", "quarantineId", "resource"}
        }
        quarantine_id = hashlib.sha256(
            json.dumps(common, separators=(",", ":"), sort_keys=True).encode()
        ).hexdigest()
        quarantine["quarantineId"] = quarantine_id
        dead_owner["quarantine_id"] = quarantine_id
        NATIVE_LAB.write_json_atomic(owner_path, dead_owner)
        NATIVE_LAB.write_json_atomic(quarantine_path, quarantine)
        self.assertTrue(NATIVE_LAB.quarantine_is_canonically_bound(quarantine))
        tampered = {**quarantine, "terminationReason": "different"}
        self.assertFalse(NATIVE_LAB.quarantine_is_canonically_bound(tampered))

        reacquired, busy = NATIVE_LAB.acquire(resource, stale_after=0)
        self.assertIsNone(reacquired)
        self.assertTrue(busy["quarantined"])

        subject, subject_sha = NATIVE_LAB.recovery_subject(resource)
        evidence = self.write_recovery_evidence(
            resource, subject, subject_sha, "recovery-evidence.json"
        )
        recovery_result = Path(self.temp.name) / "recovery-result.json"
        recovered = self.run_lab(
            "recover-quarantine",
            "--resource",
            resource,
            "--evidence",
            str(evidence),
            "--result",
            str(recovery_result),
        )
        self.assertEqual(recovered.returncode, 0, recovered.stderr)
        recovery = json.loads(recovery_result.read_text(encoding="utf-8"))
        self.assertTrue(recovery["knownProcessGroupsAbsentVerified"])
        self.assertEqual(recovery["recoverySubjectSha256"], subject_sha)
        self.assertEqual(recovery["lockedResources"], subject["lockedResources"])
        self.assertFalse(lock.exists())

        subsequent = self.run_lab(
            "run",
            "--resource",
            resource,
            "--",
            sys.executable,
            "-c",
            "raise SystemExit(0)",
        )
        self.assertEqual(subsequent.returncode, 0, subsequent.stderr)

    def test_dead_owner_without_quarantine_is_never_automatically_reclaimed(self) -> None:
        resource = "dead-owner-without-quarantine"
        context = {"run_id": "1" * 64, "primary_resource": resource}
        lock, owner = NATIVE_LAB.acquire(resource, stale_after=0, owner_context=context)
        self.assertIsNotNone(lock, owner)
        owner_path = lock / "owner.json"
        payload = json.loads(owner_path.read_text(encoding="utf-8"))
        payload["pid"] = 2**31 - 1
        NATIVE_LAB.write_json_atomic(owner_path, payload)

        reacquired, busy = NATIVE_LAB.acquire(resource, stale_after=0)
        self.assertIsNone(reacquired)
        self.assertTrue(busy["recovery_required"])
        self.assertFalse(busy["quarantined"])
        self.assertTrue(lock.exists())

    @unittest.skipIf(os.name != "posix", "POSIX quarantine recovery contract")
    def test_incomplete_initial_owner_requires_and_supports_audited_recovery(self) -> None:
        resource = "incomplete-initial-owner"
        lock = self.resource_lock(resource)
        lock.mkdir(parents=True)
        reacquired, busy = NATIVE_LAB.acquire(resource, stale_after=0)
        self.assertIsNone(reacquired)
        self.assertTrue(busy["recovery_required"])
        subject, subject_sha = NATIVE_LAB.recovery_subject(resource)
        self.assertIsNone(subject["lockRecords"][0]["ownerReceiptSha256"])
        evidence = self.write_recovery_evidence(
            resource, subject, subject_sha, "incomplete-owner-recovery.json"
        )
        result = Path(self.temp.name) / "incomplete-owner-result.json"
        recovered = self.run_lab(
            "recover-quarantine",
            "--resource",
            resource,
            "--evidence",
            str(evidence),
            "--result",
            str(result),
        )
        self.assertEqual(recovered.returncode, 0, recovered.stderr)
        self.assertFalse(lock.exists())
        self.assertEqual(
            json.loads(result.read_text(encoding="utf-8"))["recoverySubjectSha256"],
            subject_sha,
        )

    @unittest.skipIf(os.name != "posix", "POSIX quarantine recovery contract")
    def test_partial_multi_lock_recovery_is_durably_receipted_and_resumable(self) -> None:
        primary = "partial-recovery-primary"
        secondary = "ios-device:partial-recovery"
        run_id = "2" * 64
        context = {"run_id": run_id, "primary_resource": primary}
        primary_lock, _ = NATIVE_LAB.acquire(primary, 21600, context)
        secondary_lock, _ = NATIVE_LAB.acquire(secondary, 21600, context)
        locks = [(primary_lock, primary), (secondary_lock, secondary)]
        NATIVE_LAB.update_managed_lock_owners(locks, run_id)
        for path, _resource in locks:
            owner_path = path / "owner.json"
            owner = json.loads(owner_path.read_text(encoding="utf-8"))
            owner["pid"] = 2**31 - 1
            NATIVE_LAB.write_json_atomic(owner_path, owner)
        subject, subject_sha = NATIVE_LAB.recovery_subject(primary)
        self.assertEqual(subject["lockedResources"], sorted([primary, secondary]))
        evidence = self.write_recovery_evidence(
            primary, subject, subject_sha, "partial-recovery-evidence.json"
        )
        result = Path(self.temp.name) / "partial-recovery-result.json"
        args = argparse.Namespace(resource=primary, evidence=str(evidence), result=str(result))
        real_rmtree = NATIVE_LAB.shutil.rmtree
        deletion_count = 0

        def fail_after_first_delete(path, *call_args, **call_kwargs):
            nonlocal deletion_count
            real_rmtree(path, *call_args, **call_kwargs)
            deletion_count += 1
            if deletion_count == 1:
                raise OSError("injected interruption after lock deletion")

        with mock.patch.object(NATIVE_LAB.shutil, "rmtree", side_effect=fail_after_first_delete):
            with contextlib.redirect_stdout(io.StringIO()):
                first_code = NATIVE_LAB.recover_quarantine(args)
        self.assertEqual(first_code, 75)
        journal = (
            Path(self.state_dir)
            / "recoveries"
            / subject_sha
            / "transaction.json"
        )
        receipt = journal.with_name("receipt.json")
        self.assertTrue(journal.exists())
        self.assertTrue(receipt.exists())
        partial = json.loads(journal.read_text(encoding="utf-8"))
        self.assertEqual(partial["state"], "blocked")
        self.assertIsNotNone(partial["releasePendingResource"])
        self.assertEqual(sum(path.exists() for path, _resource in locks), 1)

        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            second_code = NATIVE_LAB.recover_quarantine(args)
        self.assertEqual(second_code, 0)
        completed = json.loads(journal.read_text(encoding="utf-8"))
        self.assertEqual(completed["state"], "recovered")
        self.assertEqual(completed["releasedResources"], subject["lockedResources"])
        self.assertTrue(all(not path.exists() for path, _resource in locks))
        published = json.loads(result.read_text(encoding="utf-8"))
        self.assertEqual(published["status"], "recovered")
        self.assertEqual(json.loads(output.getvalue()), published)

    @unittest.skipIf(os.name != "posix", "POSIX quarantine recovery contract")
    def test_recovery_defers_term_until_release_receipt_is_durable(self) -> None:
        resource = "signalled-recovery"
        context = {"run_id": "3" * 64, "primary_resource": resource}
        lock, _ = NATIVE_LAB.acquire(resource, 21600, context)
        owner_path = lock / "owner.json"
        owner = json.loads(owner_path.read_text(encoding="utf-8"))
        owner["pid"] = 2**31 - 1
        NATIVE_LAB.write_json_atomic(owner_path, owner)
        subject, subject_sha = NATIVE_LAB.recovery_subject(resource)
        evidence = self.write_recovery_evidence(
            resource, subject, subject_sha, "signalled-recovery-evidence.json"
        )
        result = Path(self.temp.name) / "signalled-recovery-result.json"
        args = argparse.Namespace(resource=resource, evidence=str(evidence), result=str(result))
        real_rmtree = NATIVE_LAB.shutil.rmtree
        signal_sent = False

        def delete_then_signal(path, *call_args, **call_kwargs):
            nonlocal signal_sent
            real_rmtree(path, *call_args, **call_kwargs)
            if not signal_sent:
                signal_sent = True
                os.kill(os.getpid(), signal.SIGTERM)

        with mock.patch.object(NATIVE_LAB.shutil, "rmtree", side_effect=delete_then_signal):
            with contextlib.redirect_stdout(io.StringIO()):
                code = NATIVE_LAB.recover_quarantine(args)
        self.assertEqual(code, 128 + signal.SIGTERM)
        self.assertFalse(lock.exists())
        receipt = json.loads(result.read_text(encoding="utf-8"))
        self.assertEqual(receipt["status"], "recovered")
        self.assertEqual(receipt["deferredSignal"], signal.SIGTERM)
        journal = (
            Path(self.state_dir)
            / "recoveries"
            / subject_sha
            / "transaction.json"
        )
        self.assertEqual(json.loads(journal.read_text(encoding="utf-8"))["state"], "recovered")

    @unittest.skipIf(os.name != "posix", "POSIX quarantine recovery contract")
    def test_concurrent_recovery_cannot_delete_a_fresh_managed_lock(self) -> None:
        resource = "concurrent-recovery-primary"
        context = {"run_id": "4" * 64, "primary_resource": resource}
        lock, owner = NATIVE_LAB.acquire(resource, 21600, context)
        self.assertIsNotNone(lock, owner)
        owner_path = lock / "owner.json"
        dead_owner = json.loads(owner_path.read_text(encoding="utf-8"))
        dead_owner["pid"] = 2**31 - 1
        NATIVE_LAB.write_json_atomic(owner_path, dead_owner)
        subject, subject_sha = NATIVE_LAB.recovery_subject(resource)
        evidence = self.write_recovery_evidence(
            resource, subject, subject_sha, "concurrent-recovery-evidence.json"
        )
        first_result = Path(self.temp.name) / "concurrent-recovery-first.json"
        second_result = Path(self.temp.name) / "concurrent-recovery-second.json"
        deleted = Path(self.temp.name) / "authorized-lock-deleted"
        continue_recovery = Path(self.temp.name) / "continue-recovery"
        recovery_driver = Path(self.temp.name) / "paused-recovery.py"
        recovery_driver.write_text(
            """\
import argparse
import importlib.util
import sys
import time
from pathlib import Path

lab_path, deleted_path, continue_path, resource, evidence, result = sys.argv[1:]
spec = importlib.util.spec_from_file_location("native_lab_paused_recovery", lab_path)
native_lab = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native_lab)
real_rmtree = native_lab.shutil.rmtree

def delete_then_pause(path, *args, **kwargs):
    real_rmtree(path, *args, **kwargs)
    Path(deleted_path).write_text("deleted\\n", encoding="utf-8")
    while not Path(continue_path).exists():
        time.sleep(0.01)

native_lab.shutil.rmtree = delete_then_pause
raise SystemExit(
    native_lab.recover_quarantine(
        argparse.Namespace(resource=resource, evidence=evidence, result=result)
    )
)
""",
            encoding="utf-8",
        )
        environment = os.environ.copy()
        environment["NVPN_NATIVE_LAB_STATE_DIR"] = self.state_dir
        first = subprocess.Popen(
            [
                sys.executable,
                str(recovery_driver),
                str(LAB),
                str(deleted),
                str(continue_recovery),
                resource,
                str(evidence),
                str(first_result),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=environment,
            start_new_session=True,
        )
        second = None
        fresh = None
        try:
            self.wait_for_path(deleted)
            self.assertFalse(lock.exists())
            second = self.start_lab(
                "recover-quarantine",
                "--resource",
                resource,
                "--evidence",
                str(evidence),
                "--result",
                str(second_result),
            )
            time.sleep(0.1)
            self.assertIsNone(second.poll(), "second recovery did not wait on the subject mutex")

            fresh_ready = Path(self.temp.name) / "fresh-managed-ready"
            child_source = (
                "import signal,time,sys; from pathlib import Path; stopped=[]; "
                "signal.signal(signal.SIGTERM, lambda *_: stopped.append(True)); "
                "Path(sys.argv[1]).write_text('ready\\n', encoding='utf-8'); "
                "exec(\"while not stopped:\\n time.sleep(0.01)\")"
            )
            fresh = self.start_lab(
                "run",
                "--resource",
                resource,
                "--signal-grace",
                "1",
                "--",
                sys.executable,
                "-c",
                child_source,
                str(fresh_ready),
            )
            self.wait_for_path(fresh_ready)
            fresh_owner = json.loads(owner_path.read_text(encoding="utf-8"))
            self.assertEqual(fresh_owner["pid"], fresh.pid)

            continue_recovery.write_text("continue\n", encoding="utf-8")
            first_stdout, first_stderr = first.communicate(timeout=5)
            self.assertEqual(first.returncode, 0, first_stderr)
            second_stdout, second_stderr = second.communicate(timeout=5)
            self.assertEqual(second.returncode, 0, second_stderr)
            self.assertIsNone(fresh.poll(), "recovery terminated the fresh managed run")
            self.assertTrue(lock.is_dir())
            self.assertEqual(
                json.loads(owner_path.read_text(encoding="utf-8"))["pid"], fresh.pid
            )

            first_receipt = json.loads(first_result.read_text(encoding="utf-8"))
            second_receipt = json.loads(second_result.read_text(encoding="utf-8"))
            self.assertEqual(first_receipt, second_receipt)
            self.assertEqual(json.loads(first_stdout), first_receipt)
            self.assertEqual(json.loads(second_stdout), second_receipt)
            journal = (
                Path(self.state_dir)
                / "recoveries"
                / subject_sha
                / "transaction.json"
            )
            transaction = json.loads(journal.read_text(encoding="utf-8"))
            self.assertEqual(transaction["state"], "recovered")
            self.assertEqual(transaction["releasedResources"], [resource])
            self.assertIsNone(transaction["releasePendingResource"])
        finally:
            continue_recovery.touch(exist_ok=True)
            if first.poll() is None:
                self.stop_process(first)
            if second is not None and second.poll() is None:
                self.stop_process(second)
            if fresh is not None:
                self.stop_process(fresh)

    @unittest.skipIf(os.name != "posix", "POSIX quarantine recovery contract")
    def test_failed_recoverer_cannot_regress_a_completed_recovery_journal(self) -> None:
        resource = "monotonic-recovery-primary"
        context = {"run_id": "5" * 64, "primary_resource": resource}
        lock, owner = NATIVE_LAB.acquire(resource, 21600, context)
        self.assertIsNotNone(lock, owner)
        owner_path = lock / "owner.json"
        dead_owner = json.loads(owner_path.read_text(encoding="utf-8"))
        dead_owner["pid"] = 2**31 - 1
        NATIVE_LAB.write_json_atomic(owner_path, dead_owner)
        subject, subject_sha = NATIVE_LAB.recovery_subject(resource)
        evidence = self.write_recovery_evidence(
            resource, subject, subject_sha, "monotonic-recovery-evidence.json"
        )
        first_result = Path(self.temp.name) / "monotonic-recovery-first.json"
        second_result = Path(self.temp.name) / "monotonic-recovery-second.json"
        first_mutex_released = Path(self.temp.name) / "first-mutex-released"
        allow_first_error_handler = Path(self.temp.name) / "allow-first-error-handler"
        recovery_driver = Path(self.temp.name) / "failed-recovery.py"
        recovery_driver.write_text(
            """\
import argparse
import contextlib
import importlib.util
import sys
import time
from pathlib import Path

lab_path, released_path, continue_path, resource, evidence, result = sys.argv[1:]
spec = importlib.util.spec_from_file_location("native_lab_failed_recovery", lab_path)
native_lab = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native_lab)
real_mutex = native_lab.recovery_mutex
real_rmtree = native_lab.shutil.rmtree
paused = False

@contextlib.contextmanager
def pause_after_first_mutex_release(subject):
    global paused
    try:
        with real_mutex(subject):
            yield
    finally:
        if not paused:
            paused = True
            Path(released_path).write_text("released\\n", encoding="utf-8")
            while not Path(continue_path).exists():
                time.sleep(0.01)

def delete_then_fail(path, *args, **kwargs):
    real_rmtree(path, *args, **kwargs)
    raise OSError("injected failure after authorized inode deletion")

native_lab.recovery_mutex = pause_after_first_mutex_release
native_lab.shutil.rmtree = delete_then_fail
raise SystemExit(
    native_lab.recover_quarantine(
        argparse.Namespace(resource=resource, evidence=evidence, result=result)
    )
)
""",
            encoding="utf-8",
        )
        environment = os.environ.copy()
        environment["NVPN_NATIVE_LAB_STATE_DIR"] = self.state_dir
        first = subprocess.Popen(
            [
                sys.executable,
                str(recovery_driver),
                str(LAB),
                str(first_mutex_released),
                str(allow_first_error_handler),
                resource,
                str(evidence),
                str(first_result),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=environment,
            start_new_session=True,
        )
        second = None
        try:
            self.wait_for_path(first_mutex_released)
            self.assertFalse(lock.exists())
            second = self.run_lab(
                "recover-quarantine",
                "--resource",
                resource,
                "--evidence",
                str(evidence),
                "--result",
                str(second_result),
            )
            self.assertEqual(second.returncode, 0, second.stderr)
            journal = (
                Path(self.state_dir)
                / "recoveries"
                / subject_sha
                / "transaction.json"
            )
            recovered_before_first_resumes = json.loads(
                journal.read_text(encoding="utf-8")
            )
            self.assertEqual(recovered_before_first_resumes["state"], "recovered")

            allow_first_error_handler.write_text("continue\n", encoding="utf-8")
            _first_stdout, first_stderr = first.communicate(timeout=5)
            self.assertEqual(first.returncode, 75, first_stderr)
            recovered_after_first_finishes = json.loads(
                journal.read_text(encoding="utf-8")
            )
            self.assertEqual(
                recovered_after_first_finishes, recovered_before_first_resumes
            )
            durable_receipt = json.loads(
                journal.with_name("receipt.json").read_text(encoding="utf-8")
            )
            self.assertEqual(
                durable_receipt,
                json.loads(second_result.read_text(encoding="utf-8")),
            )
            self.assertEqual(durable_receipt["status"], "recovered")
        finally:
            allow_first_error_handler.touch(exist_ok=True)
            if first.poll() is None:
                self.stop_process(first)

    @unittest.skipIf(os.name != "posix", "POSIX signal precedence contract")
    def test_secondary_acquisition_cancellation_reports_only_acquired_subset(self) -> None:
        primary = "subset-primary"
        result = Path(self.temp.name) / "subset-result.json"
        args = argparse.Namespace(
            resource=primary,
            stale_after=21600,
            health=["android:first", "ios-device:second"],
            allocation_env=[],
            command=["--", sys.executable, "-c", "raise SystemExit(0)"],
            timeout=0,
            signal_grace=1,
            result=str(result),
        )
        checks = [
            {"spec": "android:first", "available": True, "allocation": "first"},
            {"spec": "ios-device:second", "available": True, "allocation": "second"},
        ]
        real_acquire = NATIVE_LAB.acquire
        secondary_calls = 0

        def interrupt_after_first_secondary(resource, stale_after, owner_context=None):
            nonlocal secondary_calls
            acquired = real_acquire(resource, stale_after, owner_context)
            if resource != primary:
                secondary_calls += 1
                if secondary_calls == 1:
                    os.kill(os.getpid(), signal.SIGTERM)
            return acquired

        with mock.patch.object(NATIVE_LAB, "health_report", return_value=checks):
            with mock.patch.object(NATIVE_LAB, "acquire", side_effect=interrupt_after_first_secondary):
                with contextlib.redirect_stdout(io.StringIO()):
                    code = NATIVE_LAB.run_managed(args)
        report = json.loads(result.read_text(encoding="utf-8"))
        self.assertEqual(code, 128 + signal.SIGTERM)
        self.assertEqual(report["reserved_resources"], ["android:first"])
        self.assertFalse(self.resource_lock(primary).exists())
        self.assertFalse(self.resource_lock("android:first").exists())

    def test_recovery_rejects_non_posix_before_filesystem_access(self) -> None:
        args = argparse.Namespace(
            resource="unused",
            evidence="/does/not/exist",
            result="/does/not/exist",
        )
        with mock.patch.object(NATIVE_LAB.os, "name", "nt"):
            self.assertEqual(NATIVE_LAB.recover_quarantine(args), 2)


if __name__ == "__main__":
    unittest.main()
