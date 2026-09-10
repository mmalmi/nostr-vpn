#!/usr/bin/env python3
"""Exercise the installed-app proof consumed by the production artifact audit."""

import hashlib
import json
import os
from pathlib import Path
import plistlib
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent


class ArtifactReadbackTest(unittest.TestCase):
    def test_requires_exact_usb_device_source_signer_and_version(self):
        with tempfile.TemporaryDirectory(prefix="nvpn-ios-readback-") as directory:
            root = Path(directory)
            app = root / "app"
            tunnel = app / "PlugIns/Nostr VPN Tunnel.appex"
            tunnel.mkdir(parents=True)
            for path in [app, tunnel]:
                (path / "embedded.mobileprovision").write_bytes(b"profile fixture")
            info = {"CFBundleVersion": "7", "CFBundleShortVersionString": "1.2.3",
                    "NVPNBuildGitSha": "a" * 40}
            (app / "Info.plist").write_bytes(plistlib.dumps(info))
            (root / "plan.xctestrun").write_bytes(b"plan fixture")
            device_sha = hashlib.sha256(b"fixture-device").hexdigest()
            (root / "device.json").write_text(json.dumps({"deviceIdentifierSha256": device_sha}))
            payload = {
                "provider": "apple-installation-proxy-usb", "bundleIdentifier": "test.nvpn",
                "selectedPhysicalDeviceIdentifierSha256": device_sha,
                "applicationType": "User", "profileValidated": True,
                "signerIdentitySha256": "b" * 64, "appGitSha": "a" * 40,
                "bundleVersion": "7", "version": "1.2.3",
            }
            values = [root / "receipt.json", "cd", "cd", "c" * 64, "d" * 64,
                      "e" * 64, "f" * 64, "a" * 40, "a" * 40, "a" * 40,
                      app / "Info.plist", root / "installed.json", "test.nvpn",
                      root / "device.json", app, root / "derived", root / "plan.xctestrun",
                      "a" * 40, "0.1.0", "a" * 64, "a" * 64, "a" * 64,
                      "a" * 64, "b" * 64]
            cases = [(None, None)] + [
                ("provider", "unverified"), ("bundleIdentifier", "other.app"),
                ("selectedPhysicalDeviceIdentifierSha256", "0" * 64),
                ("applicationType", "System"), ("profileValidated", False),
                ("signerIdentitySha256", "0" * 64), ("appGitSha", "0" * 40),
                ("bundleVersion", "8"), ("version", "1.2.4"),
            ]
            for key, value in cases:
                with self.subTest(field=key):
                    candidate = dict(payload)
                    if key:
                        candidate[key] = value
                    (root / "installed.json").write_text(json.dumps(candidate))
                    result = subprocess.run([
                        "bash", "-c",
                        'source "$1/scripts/lib-mobile-ios-release-artifact.sh"; '
                        'shift; ios_release_network_write_artifact_receipt "$@"',
                        "artifact-readback", str(ROOT), *map(str, values),
                    ], capture_output=True, text=True, timeout=5, env=os.environ)
                    if key is None:
                        self.assertEqual(result.returncode, 0, result.stderr)
                        receipt = json.loads((root / "receipt.json").read_text())
                        self.assertEqual(receipt["installedIdentityProvider"], payload["provider"])
                        self.assertEqual(receipt["installedSignerIdentitySha256"], "b" * 64)
                    else:
                        self.assertNotEqual(result.returncode, 0)
                        self.assertIn("installed iOS", result.stderr)


if __name__ == "__main__":
    unittest.main()
