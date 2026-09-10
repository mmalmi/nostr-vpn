#!/usr/bin/env python3
"""Capture xcodebuild output and independently sample iOS Release processes."""

from __future__ import annotations

import concurrent.futures
import json
import re
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

from ios_packet_tunnel_processes import read_process_inventory


MARKER = re.compile(
    r"NVPN_IOS_UNDERLAY_SWITCH_(?P<cycle>1)_"
    r"(?P<phase>REQUESTED|OUTAGE|RECOVERY_REQUESTED|"
    r"UNDERLAY_VALIDATED|PAYLOAD_RECOVERY|VERIFIED)_MS="
    r"(?P<value>\d+)"
)
ACTIVE = re.compile(
    r"NVPN_IOS_RELEASE_ACTIVE_SESSION_(?P<phase>BEGIN|END)_MS=\d+"
)
ACTIVE_TUNNEL_CHECKPOINT = re.compile(
    r"NVPN_IOS_(?P<name>"
    r"UNDERLAY_SWITCH_1_(?:REQUESTED|OUTAGE|RECOVERY_REQUESTED|"
    r"UNDERLAY_VALIDATED|PAYLOAD_RECOVERY|VERIFIED)"
    r"|RELEASE_BACKGROUND_\d+_REQUESTED"
    r"|RELEASE_FOREGROUND_\d+_VERIFIED"
    r")"
)
DIRECT_READY = re.compile(
    r"NVPN_IOS_(?P<name>RELEASE_CONNECTED_DIRECT(?:_RELAUNCH)?_READY)=1"
)
RUN_ID = re.compile(r"NVPN_XCUITEST_RUN_ID=(?P<value>[^\s]+)")
DIRECT_CHECKPOINTS = frozenset(
    {
        "release_connected_direct_passed",
        "release_connected_direct_relaunch_passed",
    }
)
DIRECT_READY_CHECKPOINTS = {
    "release_connected_direct_ready": "release_connected_direct_passed",
    "release_connected_direct_relaunch_ready": (
        "release_connected_direct_relaunch_passed"
    ),
}
DIRECT_SAMPLE_TIMEOUT_SECONDS = 25
DIRECT_ACK_TIMEOUT_SECONDS = 5
DIRECT_SAMPLE_RETRY_SECONDS = 0.25


def valid_process_sample(sample: dict[str, object]) -> bool:
    return (
        not sample.get("error")
        and isinstance(sample.get("appPids"), list)
        and len(sample["appPids"]) == 1
        and isinstance(sample.get("packetTunnelPids"), list)
        and len(sample["packetTunnelPids"]) == 1
    )


def process_ids(processes: dict[int, str]) -> tuple[list[int], list[int]]:
    # The signed app and extension use these exact executable names. Require
    # one of each from a complete authenticated OS-trace process inventory.
    return (
        sorted(pid for pid, name in processes.items() if name == "Nostr VPN"),
        sorted(pid for pid, name in processes.items() if name == "Nostr VPN Tunnel"),
    )


class ProcessSampler:
    def __init__(
        self,
        device: str,
        summary_path: Path,
        runner_bundle: str | None = None,
    ) -> None:
        self.device = device
        self.summary_path = summary_path
        self.runner_bundle = runner_bundle
        self.active = threading.Event()
        self.stopped = threading.Event()
        self.lock = threading.Lock()
        self.samples_lock = threading.Lock()
        self.checkpoint = "active-session-begin"
        self.required_checkpoints: set[str] = set()
        self.checkpoint_executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=4,
            thread_name_prefix="ios-process-checkpoint",
        )
        self.checkpoint_futures: list[
            concurrent.futures.Future[bool]
        ] = []
        self.begin_seen = False
        self.end_seen = False
        self.samples: list[dict[str, object]] = []
        self.direct_acknowledgements: set[str] = set()
        self.direct_errors: list[str] = []
        self.thread = threading.Thread(target=self._run, daemon=True)

    def start(self) -> None:
        self.thread.start()

    def begin(self) -> None:
        self.begin_seen = True
        self.update_checkpoint("active-session-begin")
        self.active.set()

    def update_checkpoint(self, checkpoint: str) -> None:
        normalized = checkpoint.lower()
        should_sample = False
        with self.lock:
            if (
                self.end_seen
                and normalized not in DIRECT_CHECKPOINTS
                and normalized != "active-session-end"
            ):
                return
            self.checkpoint = normalized
            if normalized not in self.required_checkpoints:
                self.required_checkpoints.add(normalized)
                should_sample = True
        if should_sample:
            future = self.checkpoint_executor.submit(
                self._sample_checkpoint, normalized
            )
            with self.lock:
                self.checkpoint_futures.append(future)

    def observe_direct_checkpoint(self, ready: str, run_id: str) -> None:
        checkpoint = DIRECT_READY_CHECKPOINTS[ready.lower()]
        with self.lock:
            if checkpoint in self.required_checkpoints:
                return
            self.required_checkpoints.add(checkpoint)
        future = self.checkpoint_executor.submit(
            self._observe_direct_checkpoint,
            checkpoint,
            run_id,
        )
        with self.lock:
            self.checkpoint_futures.append(future)

    def stop(self) -> None:
        with self.lock:
            self.end_seen = True
        self.update_checkpoint("active-session-end")
        self.stopped.set()

    def finish(self, report_errors: bool = True) -> int:
        self.active.set()
        self.stopped.set()
        self.thread.join(timeout=7)
        errors: list[str] = []
        with self.lock:
            checkpoint_futures = list(self.checkpoint_futures)
        done, pending = concurrent.futures.wait(
            checkpoint_futures,
            timeout=12,
        )
        if pending:
            errors.append(
                f"{len(pending)} checkpoint process observations did not finish"
            )
        for future in done:
            try:
                future.result()
            except Exception as error:  # pragma: no cover - defensive boundary
                errors.append(
                    "checkpoint process observation raised "
                    f"{type(error).__name__}"
                )
        self.checkpoint_executor.shutdown(
            wait=False,
            cancel_futures=True,
        )
        if self.thread.is_alive():
            errors.append("process sampler did not stop")
        if not self.begin_seen:
            errors.append("active-session begin marker was missing")
        if not self.end_seen:
            errors.append("active-session end marker was missing")
        with self.samples_lock:
            samples = list(self.samples)
        if len(samples) < 2:
            errors.append(
                f"only {len(samples)} active-session process observations"
            )
        app_pids: set[int] = set()
        tunnel_pids: set[int] = set()
        direct_checkpoint_processes: dict[str, dict[str, int]] = {}
        valid_checkpoints: set[str] = set()
        valid_direct_checkpoints = {
            str(sample.get("checkpoint", ""))
            for sample in samples
            if valid_process_sample(sample)
            and sample.get("checkpoint") in DIRECT_CHECKPOINTS
        }
        for index, sample in enumerate(samples, start=1):
            checkpoint = str(sample.get("checkpoint", ""))
            if (
                checkpoint in valid_direct_checkpoints
                and not valid_process_sample(sample)
            ):
                continue
            if sample.get("error"):
                errors.append(
                    f"process observation {index}: {sample['error']}"
                )
                continue
            app = sample.get("appPids")
            tunnel = sample.get("packetTunnelPids")
            if not isinstance(app, list) or len(app) != 1:
                errors.append(
                    f"process observation {index} appPids={app!r}"
                )
            if not isinstance(tunnel, list) or len(tunnel) != 1:
                errors.append(
                    f"process observation {index} packetTunnelPids={tunnel!r}"
                )
            if valid_process_sample(sample):
                valid_checkpoints.add(checkpoint)
                if checkpoint in DIRECT_CHECKPOINTS:
                    direct_checkpoint_processes[checkpoint] = {
                        "appProcessIdentifier": int(app[0]),
                        "packetTunnelProcessIdentifier": int(tunnel[0]),
                    }
                else:
                    app_pids.add(int(app[0]))
                    tunnel_pids.add(int(tunnel[0]))
        if len(app_pids) != 1:
            errors.append(f"distinct app PIDs={sorted(app_pids)}")
        if len(tunnel_pids) != 1:
            errors.append(
                f"distinct packet-tunnel PIDs={sorted(tunnel_pids)}"
            )
        with self.lock:
            required_checkpoints = set(self.required_checkpoints)
            direct_acknowledgements = set(self.direct_acknowledgements)
            direct_errors = list(self.direct_errors)
        errors.extend(direct_errors)
        missing_acknowledgements = sorted(
            (required_checkpoints & DIRECT_CHECKPOINTS)
            - direct_acknowledgements
        )
        if missing_acknowledgements:
            errors.append(
                "Direct checkpoints without runner acknowledgement="
                f"{missing_acknowledgements}"
            )
        missing_checkpoints = sorted(required_checkpoints - valid_checkpoints)
        if missing_checkpoints:
            errors.append(
                "checkpoints without a valid process observation="
                f"{missing_checkpoints}"
            )
        summary = {
            "activeSessionBeginSeen": self.begin_seen,
            "activeSessionEndSeen": self.end_seen,
            "appProcessIdentifiers": sorted(app_pids),
            "directCheckpointProcesses": direct_checkpoint_processes,
            "directRunnerAcknowledgements": sorted(direct_acknowledgements),
            "observedCheckpoints": sorted(valid_checkpoints),
            "packetTunnelProcessIdentifiers": sorted(tunnel_pids),
            "passed": not errors,
            "requiredCheckpoints": sorted(required_checkpoints),
            "sampleCount": len(samples),
            "samples": samples,
        }
        if errors:
            summary["errors"] = errors
        self.summary_path.parent.mkdir(parents=True, exist_ok=True)
        self.summary_path.write_text(
            json.dumps(summary, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        if errors and report_errors:
            print(
                "iOS Release process continuity failed: " + "; ".join(errors),
                file=sys.stderr,
            )
        if errors:
            return 1
        return 0

    def _run(self) -> None:
        self.active.wait()
        while not self.stopped.is_set():
            with self.lock:
                checkpoint = self.checkpoint
            self._sample(checkpoint)
            self.stopped.wait(0.25)

    def _sample_checkpoint(self, checkpoint: str) -> bool:
        if checkpoint not in DIRECT_CHECKPOINTS:
            return self._sample(checkpoint)
        deadline = time.monotonic() + DIRECT_SAMPLE_TIMEOUT_SECONDS
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            if self._sample(checkpoint, timeout=min(5, remaining)):
                return True
            time.sleep(
                min(
                    DIRECT_SAMPLE_RETRY_SECONDS,
                    max(0, deadline - time.monotonic()),
                )
            )

    def _observe_direct_checkpoint(
        self,
        checkpoint: str,
        run_id: str,
    ) -> bool:
        if not self._sample_checkpoint(checkpoint):
            with self.lock:
                self.direct_errors.append(
                    f"{checkpoint} had no real app and PacketTunnel process within "
                    f"{DIRECT_SAMPLE_TIMEOUT_SECONDS}s"
                )
            return False
        error = self._write_runner_acknowledgement(checkpoint, run_id)
        if error:
            with self.lock:
                self.direct_errors.append(error)
            return False
        with self.lock:
            self.direct_acknowledgements.add(checkpoint)
        return True

    def _write_runner_acknowledgement(
        self,
        checkpoint: str,
        run_id: str,
    ) -> str | None:
        if not self.runner_bundle:
            return "Direct process observation has no XCTest runner bundle"
        contents = (
            f"NVPN_XCUITEST_RUN_ID={run_id}\n"
            f"NVPN_IOS_HOST_PROCESS_OBSERVED={checkpoint}\n"
        )
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as source:
            source.write(contents)
            source.flush()
            try:
                completed = subprocess.run(
                    [
                        "ios-deploy",
                        "--id",
                        self.device,
                        "--no-wifi",
                        "--bundle_id",
                        self.runner_bundle,
                        "--upload",
                        source.name,
                        "--to",
                        "Documents/nvpn-host-process-ack.log",
                    ],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=DIRECT_ACK_TIMEOUT_SECONDS,
                    check=False,
                )
            except (OSError, subprocess.TimeoutExpired) as error:
                return (
                    f"{checkpoint} runner acknowledgement failed: "
                    f"{type(error).__name__}"
                )
        if completed.returncode != 0:
            return (
                f"{checkpoint} runner acknowledgement copy failed with status "
                f"{completed.returncode}"
            )
        return None

    def _sample(self, checkpoint: str, timeout: float = 5) -> bool:
        timestamp_ms = time.time_ns() // 1_000_000
        sample: dict[str, object] = {
            "checkpoint": checkpoint,
            "observedAtMilliseconds": timestamp_ms,
        }
        try:
            processes, inventory_sha = read_process_inventory(self.device, timeout)
            app, tunnel = process_ids(processes)
            sample.update({
                "appPids": app,
                "packetTunnelPids": tunnel,
                "provider": "apple-os-trace-relay-pidlist",
                "inventorySha256": inventory_sha,
                "processCount": len(processes),
            })
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            sample["error"] = type(error).__name__
        with self.samples_lock:
            self.samples.append(sample)
        return valid_process_sample(sample)


def main() -> int:
    if len(sys.argv) not in (3, 6):
        raise SystemExit(
            "usage: capture-mobile-ios-underlay-output.py "
            "XCODE_LOG HOST_MARKERS [DEVICE PROCESS_SUMMARY RUNNER_BUNDLE]"
        )
    log_path = Path(sys.argv[1])
    marker_path = Path(sys.argv[2])
    log_path.parent.mkdir(parents=True, exist_ok=True)
    marker_path.parent.mkdir(parents=True, exist_ok=True)
    sampler = (
        ProcessSampler(sys.argv[3], Path(sys.argv[4]), sys.argv[5])
        if len(sys.argv) == 6
        else None
    )
    if sampler:
        sampler.start()
    seen: set[str] = set()
    duplicates: set[str] = set()
    runner_run_id = ""
    with (
        log_path.open("w", encoding="utf-8", buffering=1) as log,
        marker_path.open("w", encoding="utf-8", buffering=1) as markers,
    ):
        for line in sys.stdin:
            received_ms = time.time_ns() // 1_000_000
            log.write(line)
            run_id_match = RUN_ID.search(line)
            if run_id_match:
                runner_run_id = run_id_match.group("value")
            active_match = ACTIVE.search(line)
            if active_match and sampler:
                if active_match.group("phase") == "BEGIN":
                    sampler.begin()
                else:
                    sampler.stop()
            checkpoint_match = ACTIVE_TUNNEL_CHECKPOINT.search(line)
            if checkpoint_match and sampler:
                sampler.update_checkpoint(checkpoint_match.group("name"))
            direct_ready_match = DIRECT_READY.search(line)
            if direct_ready_match and sampler:
                if not runner_run_id:
                    with sampler.lock:
                        sampler.direct_errors.append(
                            "Direct process observation request had no XCTest run ID"
                        )
                else:
                    sampler.observe_direct_checkpoint(
                        direct_ready_match.group("name"), runner_run_id
                    )
            match = MARKER.search(line)
            if not match:
                continue
            name = (
                f"switch_{match.group('cycle')}_"
                f"{match.group('phase').lower()}"
            )
            if name in seen:
                duplicates.add(name)
            seen.add(name)
            value = (
                match.group("value")
                if match.group("phase") == "PAYLOAD_RECOVERY"
                else str(received_ms)
            )
            markers.write(f"{name}\t{value}\n")
    # The caller gives xcodebuild's status precedence. Keep continuity details
    # in the receipt so a primary XCTest failure is not obscured by derivative
    # missing-END or missing-process diagnostics.
    if sampler:
        sampler.finish(report_errors=False)
    if duplicates:
        print(
            "duplicate iOS underlay markers: " + ", ".join(sorted(duplicates)),
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
