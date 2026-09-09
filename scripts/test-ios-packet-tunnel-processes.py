#!/usr/bin/env python3
"""Exercise the production shell entry point with a controlled OS-trace service."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parent.parent


class InventoryTest(unittest.TestCase):
    def run_case(self, mode):
        with tempfile.TemporaryDirectory(prefix="nvpn-ios-process-test-") as directory:
            root = Path(directory)
            tool = root / "idevicesyslog"
            tool.write_text(f"#!{sys.executable}\n" + '''
import os, pathlib, sys, time
assert sys.argv[1:] == ['-u', 'fixture-device', 'pidlist']
mode = os.environ['INVENTORY_TEST_MODE']
counter = pathlib.Path(os.environ['INVENTORY_TEST_COUNTER'])
attempt = int(counter.read_text()) + 1 if counter.exists() else 1
counter.write_text(str(attempt))
if mode == 'unavailable': sys.exit(2)
if mode == 'blocked': time.sleep(30)
if mode == 'missing-system': print('2 app'); sys.exit(0)
print('1 launchd\\n2 SpringBoard')
if mode == 'malformed': print('not-a-process')
if mode == 'duplicate': print('2 another-app')
if mode == 'live' or (mode == 'stopping' and attempt == 1): print('7 Nostr VPN Tunnel')
''')
            tool.chmod(0o755)
            output = root / "receipt.json"
            env = {**os.environ, "PATH": f"{root}:{os.environ['PATH']}",
                   "INVENTORY_TEST_MODE": mode, "INVENTORY_TEST_COUNTER": str(root / "count")}
            started = time.monotonic()
            result = subprocess.run([
                "bash", "-c",
                'ROOT="$1"; source "$ROOT/scripts/lib-mobile-ios-release-network.sh"; '
                'ios_release_network_require_packet_tunnel_stopped fixture-device "$2" 1',
                "inventory-test", str(ROOT), str(output),
            ], env=env, capture_output=True, text=True, timeout=4)
            receipt = json.loads(output.read_text()) if output.exists() else None
            return result, receipt, time.monotonic() - started

    def test_absent_and_stopping(self):
        for mode in ["absent", "stopping"]:
            with self.subTest(mode=mode):
                result, receipt, _ = self.run_case(mode)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(receipt["packetTunnelProcesses"], [])
                self.assertEqual(receipt["provider"], "apple-os-trace-relay-pidlist")

    def test_rejects_unproven_shutdown(self):
        for mode in ["live", "missing-system", "malformed", "duplicate", "unavailable", "blocked"]:
            with self.subTest(mode=mode):
                result, _, elapsed = self.run_case(mode)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("iOS cleanup could not", result.stderr)
                self.assertLess(elapsed, 3)


if __name__ == "__main__":
    unittest.main()
