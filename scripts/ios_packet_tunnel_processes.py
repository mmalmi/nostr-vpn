#!/usr/bin/env python3
"""Verify tunnel shutdown through Apple's OS trace service after XCTest."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("device")
    parser.add_argument("output", type=Path)
    parser.add_argument("timeout", type=float)
    args = parser.parse_args()
    if args.timeout <= 0:
        parser.error("timeout must be positive")
    deadline = time.monotonic() + args.timeout
    args.output.unlink(missing_ok=True)
    while time.monotonic() < deadline:
        try:
            result = subprocess.run(
                ["idevicesyslog", "-u", args.device, "pidlist"],
                capture_output=True,
                text=True,
                timeout=min(15, deadline - time.monotonic()),
                check=True,
            )
            processes = {}
            for line in result.stdout.splitlines():
                pid, name = line.split(maxsplit=1)
                if not pid.isdecimal() or int(pid) <= 0 or int(pid) in processes:
                    raise ValueError("invalid or duplicate process identifier")
                processes[int(pid)] = name
            if processes.get(1) != "launchd" or "SpringBoard" not in processes.values():
                raise ValueError("missing system processes in inventory")
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            raise SystemExit(
                f"iOS cleanup could not inspect the process inventory ({type(error).__name__})"
            ) from None
        tunnels = [
            {"processIdentifier": pid, "name": name}
            for pid, name in processes.items()
            if name == "Nostr VPN Tunnel"
        ]
        # Retain the proof and matching processes, without other app names.
        args.output.write_text(json.dumps({
            "receiptSchema": 1,
            "provider": "apple-os-trace-relay-pidlist",
            "sampledAtUnixMs": time.time_ns() // 1_000_000,
            "processCount": len(processes),
            "inventorySha256": hashlib.sha256(result.stdout.encode()).hexdigest(),
            "packetTunnelProcesses": tunnels,
        }, indent=2) + "\n")
        if not tunnels:
            return
        time.sleep(min(0.25, max(0, deadline - time.monotonic())))
    raise SystemExit("iOS cleanup could not verify PacketTunnel stopped within its deadline")


if __name__ == "__main__":
    main()
