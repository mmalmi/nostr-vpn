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
    def run_case(self, mode, baseline=False, app=False):
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
if mode in {'app-live', 'app-duplicate'}: print('7 Nostr VPN')
if mode == 'app-duplicate': print('8 Nostr VPN')
''')
            tool.chmod(0o755)
            output = root / "receipt.json"
            env = {**os.environ, "PATH": f"{root}:{os.environ['PATH']}",
                   "INVENTORY_TEST_MODE": mode, "INVENTORY_TEST_COUNTER": str(root / "count")}
            started = time.monotonic()
            operation = (
                'IOS_RELEASE_NETWORK_PREPARED=1; IOS_RELEASE_NETWORK_DEVICE=fixture-device; '
                'NVPN_MOBILE_WG_EXIT_IOS_UI_RESULT_DIR="$3"; '
                'ios_release_network_disconnect_cleanup_inner() { echo cleanup-required >&2; return 9; }; '
                'ios_release_network_disconnect_cleanup 1'
                if baseline else
                'ios_release_network_require_packet_tunnel_stopped fixture-device "$2" 1'
            )
            if baseline:
                output = root / "mobile-ios-release-baseline-packet-tunnel-processes.json"
            if app:
                output = root / "ios-processes-final.json"
                operation = (
                    'source "$ROOT/scripts/lib-mobile-release-join-artifacts.sh"; '
                    'IOS_DEVICE=fixture-device; RESULT_DIR="$3"; release_join_assert_one_ios_process'
                )
            result = subprocess.run([
                "bash", "-c",
                'ROOT="$1"; source "$ROOT/scripts/lib-mobile-ios-release-network.sh"; '
                + operation,
                "inventory-test", str(ROOT), str(output), str(root),
            ], env=env, capture_output=True, text=True, timeout=9 if baseline else 4)
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

    def test_baseline_avoids_automation_only_with_fresh_stopped_proof(self):
        result, receipt, _ = self.run_case("absent", baseline=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(receipt["packetTunnelProcesses"], [])
        self.assertNotIn("cleanup-required", result.stderr)
        for mode in ["live", "unavailable"]:
            with self.subTest(mode=mode):
                result, _, _ = self.run_case(mode, baseline=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("cleanup-required", result.stderr)

    def test_app_singleton_requires_one_process_from_complete_inventory(self):
        result, receipt, _ = self.run_case("app-live", app=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(receipt["appProcessIdentifier"], 7)
        for mode in ["absent", "app-duplicate", "unavailable"]:
            with self.subTest(mode=mode):
                result, receipt, _ = self.run_case(mode, app=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertIsNone(receipt)


if __name__ == "__main__":
    unittest.main()
