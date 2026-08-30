#!/usr/bin/env python3
"""Fail when a launched app burns CPU while it should be idle."""

from __future__ import annotations

import argparse
import json
import os
import shlex
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path


def parse_bool(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "on"}


def generated_at() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_ps_time(raw: str) -> float:
    value = raw.strip()
    if not value:
        raise ValueError("empty ps time")
    days = 0
    if "-" in value:
        day_part, value = value.split("-", 1)
        days = int(day_part)
    parts = value.split(":")
    if len(parts) == 3:
        hours = int(parts[0])
        minutes = int(parts[1])
        seconds = float(parts[2])
    elif len(parts) == 2:
        hours = 0
        minutes = int(parts[0])
        seconds = float(parts[1])
    elif len(parts) == 1:
        hours = 0
        minutes = 0
        seconds = float(parts[0])
    else:
        raise ValueError(f"unsupported ps time: {raw!r}")
    return (days * 24 * 3600) + (hours * 3600) + (minutes * 60) + seconds


def parse_proc_stat_cpu_seconds(stat_line: str, clock_ticks: int) -> float:
    close = stat_line.rfind(")")
    if close == -1:
        raise ValueError("missing comm terminator in /proc stat line")
    fields = stat_line[close + 2 :].split()
    if len(fields) < 13:
        raise ValueError("short /proc stat line")
    # After removing pid + comm, utime/stime are original fields 14/15.
    return (int(fields[11]) + int(fields[12])) / float(clock_ticks)


def host_cpu_seconds_for_pid(pid: int) -> float:
    proc_stat = Path(f"/proc/{pid}/stat")
    if proc_stat.exists():
        clock_ticks = os.sysconf(os.sysconf_names["SC_CLK_TCK"])
        return parse_proc_stat_cpu_seconds(proc_stat.read_text(encoding="utf-8"), clock_ticks)

    try:
        raw = subprocess.check_output(
            ["ps", "-o", "time=", "-p", str(pid)],
            text=True,
            stderr=subprocess.DEVNULL,
        )
    except subprocess.CalledProcessError as error:
        raise ProcessLookupError(pid) from error
    if not raw.strip():
        raise ProcessLookupError(pid)
    return parse_ps_time(raw)


def host_cpu_seconds(pids: list[int]) -> float:
    total = 0.0
    missing = []
    for pid in pids:
        try:
            total += host_cpu_seconds_for_pid(pid)
        except (OSError, ValueError, ProcessLookupError):
            missing.append(pid)
    if missing:
        raise ProcessLookupError(f"process exited before idle CPU sample completed: {missing}")
    return total


def adb_shell(adb: str, serial: str, command: str) -> str:
    cmd = [adb]
    if serial:
        cmd += ["-s", serial]
    cmd += ["shell", command]
    return subprocess.check_output(cmd, text=True, stderr=subprocess.STDOUT).replace("\r", "")


def android_pids(adb: str, serial: str, package: str) -> list[int]:
    raw = adb_shell(adb, serial, f"pidof {shlex.quote(package)} 2>/dev/null || true")
    pids = []
    for token in raw.split():
        try:
            pids.append(int(token))
        except ValueError:
            continue
    if not pids:
        raise ProcessLookupError(f"no Android process found for {package}")
    return pids


def android_clock_ticks(adb: str, serial: str) -> int:
    try:
        raw = adb_shell(adb, serial, "getconf CLK_TCK 2>/dev/null || echo 100")
        return int(raw.strip().splitlines()[-1])
    except (subprocess.CalledProcessError, ValueError, IndexError):
        return 100


def android_cpu_seconds_for_pids(adb: str, serial: str, pids: list[int], clock_ticks: int) -> float:
    quoted = " ".join(str(pid) for pid in pids)
    command = f"for pid in {quoted}; do cat /proc/$pid/stat 2>/dev/null || exit 7; done"
    try:
        raw = adb_shell(adb, serial, command)
    except subprocess.CalledProcessError as error:
        raise ProcessLookupError("Android process exited before idle CPU sample completed") from error
    total = 0.0
    seen = 0
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        total += parse_proc_stat_cpu_seconds(line, clock_ticks)
        seen += 1
    if seen != len(pids):
        raise ProcessLookupError("Android process set changed before idle CPU sample completed")
    return total


def sample_cpu_percent(read_cpu_seconds, sample_seconds: float, settle_seconds: float) -> tuple[float, float]:
    if settle_seconds > 0:
        time.sleep(settle_seconds)
    start_cpu = read_cpu_seconds()
    start = time.monotonic()
    time.sleep(sample_seconds)
    end_cpu = read_cpu_seconds()
    elapsed = time.monotonic() - start
    if elapsed <= 0:
        raise RuntimeError("idle CPU sample elapsed time was zero")
    return max(0.0, end_cpu - start_cpu) * 100.0 / elapsed, elapsed


def write_result(path: str | None, result: dict) -> None:
    if not path:
        return
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def finish(result: dict, artifact: str | None) -> int:
    write_result(artifact, result)
    label = result["label"]
    cpu = result.get("cpuPercent")
    max_percent = result["maxPercent"]
    if result["ok"]:
        print(f"{label} idle CPU ok: {cpu:.3f}% <= {max_percent:.3f}%")
        if artifact:
            print(f"Result: {artifact}")
        return 0
    message = result.get("error") or f"{cpu:.3f}% > {max_percent:.3f}%"
    print(f"{label} idle CPU gate failed: {message}", file=sys.stderr)
    if artifact:
        print(f"Result: {artifact}", file=sys.stderr)
    return 1


def base_result(args: argparse.Namespace, mode: str) -> dict:
    return {
        "ok": False,
        "mode": mode,
        "label": args.label,
        "maxPercent": args.max_percent,
        "sampleSeconds": args.sample_seconds,
        "settleSeconds": args.settle_seconds,
        "generatedAt": generated_at(),
    }


def run_host_pid(args: argparse.Namespace) -> int:
    pids = [int(pid) for pid in args.pid]
    result = base_result(args, "host-pid")
    result["pids"] = pids
    try:
        cpu_percent, elapsed = sample_cpu_percent(
            lambda: host_cpu_seconds(pids),
            args.sample_seconds,
            args.settle_seconds,
        )
        result["cpuPercent"] = cpu_percent
        result["elapsedSeconds"] = elapsed
        result["ok"] = cpu_percent <= args.max_percent
    except Exception as error:  # noqa: BLE001 - this is a gate script.
        result["error"] = str(error)
    return finish(result, args.artifact)


def run_android_package(args: argparse.Namespace) -> int:
    result = base_result(args, "android-package")
    result["package"] = args.package
    result["serial"] = args.serial
    try:
        pids = android_pids(args.adb, args.serial, args.package)
        clock_ticks = android_clock_ticks(args.adb, args.serial)
        result["pids"] = pids
        result["clockTicks"] = clock_ticks
        cpu_percent, elapsed = sample_cpu_percent(
            lambda: android_cpu_seconds_for_pids(args.adb, args.serial, pids, clock_ticks),
            args.sample_seconds,
            args.settle_seconds,
        )
        result["cpuPercent"] = cpu_percent
        result["elapsedSeconds"] = elapsed
        result["ok"] = cpu_percent <= args.max_percent
    except Exception as error:  # noqa: BLE001 - this is a gate script.
        result["error"] = str(error)
    return finish(result, args.artifact)


def add_common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--label", default="app", help="human-readable app/check label")
    parser.add_argument("--artifact", help="JSON result path")
    parser.add_argument(
        "--max-percent",
        type=float,
        default=float(os.environ.get("NVPN_IDLE_CPU_MAX_PERCENT", "5")),
        help="maximum allowed CPU percent of one core",
    )
    parser.add_argument(
        "--sample-seconds",
        type=float,
        default=float(os.environ.get("NVPN_IDLE_CPU_SAMPLE_SECONDS", "10")),
        help="idle CPU sample duration",
    )
    parser.add_argument(
        "--settle-seconds",
        type=float,
        default=float(os.environ.get("NVPN_IDLE_CPU_SETTLE_SECONDS", "3")),
        help="settle time before sampling",
    )


def validate_common(args: argparse.Namespace) -> None:
    if args.max_percent < 0:
        raise SystemExit("--max-percent must be non-negative")
    if args.sample_seconds <= 0:
        raise SystemExit("--sample-seconds must be positive")
    if args.settle_seconds < 0:
        raise SystemExit("--settle-seconds must be non-negative")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="mode", required=True)

    host = subparsers.add_parser("host-pid", help="measure one or more host process ids")
    add_common(host)
    host.add_argument("--pid", action="append", required=True, help="process id to include")
    host.set_defaults(func=run_host_pid)

    android = subparsers.add_parser("android-package", help="measure an Android package through adb")
    add_common(android)
    android.add_argument("--adb", default=os.environ.get("ADB", "adb"))
    android.add_argument("--serial", default=os.environ.get("ANDROID_SERIAL", ""))
    android.add_argument("--package", required=True)
    android.set_defaults(func=run_android_package)

    args = parser.parse_args()
    validate_common(args)
    if parse_bool(os.environ.get("NVPN_IDLE_CPU_GATE_DEBUG", "0")):
        print(f"idle CPU gate args: {args}", file=sys.stderr)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
