#!/usr/bin/env python3
"""Check explicit target selection without installing or launching any product."""
import argparse
import copy
import pathlib
import plistlib
import tempfile
import unittest

from ios_xctestrun import rewrite_xctestrun, xctestrun_targets


class DestinationAppSelection(unittest.TestCase):
    def check_layout(self, modern):
        with tempfile.TemporaryDirectory(prefix="nvpn-target-selection-") as directory:
            root = pathlib.Path(directory)
            products = root / "DerivedData/Build/Products"
            runner = products / "Release-iphoneos/NostrVpnIosUITests-Runner.app"
            app = root / "Nostr VPN.app"
            for path in (app / "PlugIns/Nostr VPN Tunnel.appex",
                         runner / "PlugIns/NostrVpnIosUITests.xctest"):
                path.mkdir(parents=True)
            for path, bundle in ((app, "example.nvpn"),
                                 (runner, "example.nvpn.UITests.xctrunner")):
                (path / "Info.plist").write_bytes(plistlib.dumps({"CFBundleIdentifier": bundle}))
            target = {
                "BlueprintName": "NostrVpnIosUITests",
                "IsUITestBundle": True,
                "UseUITargetAppProvidedByTests": True,
                "TestBundlePath": str(runner / "PlugIns/NostrVpnIosUITests.xctest"),
                "TestHostPath": str(runner),
                "UITargetAppPath": str(app),
                "DependentProductPaths": [str(app), str(runner)],
                "EnvironmentVariables": {"RUNNER_ONLY": "retained"},
                "UITargetAppCommandLineArguments": ["must-be-cleared"],
                "UITargetAppEnvironmentVariables": {"MUST_BE_CLEARED": "1"},
            }
            payload = ({"TestConfigurations": [{"Name": "Release", "TestTargets": [target]}]}
                       if modern else {"NostrVpnIosUITests": target})
            source = root / "retained.xctestrun"
            output = root / "case.xctestrun"
            original = plistlib.dumps(payload)
            source.write_bytes(original)
            products_before = {p: p.read_bytes() for p in root.rglob("Info.plist")}
            rewrite_xctestrun(argparse.Namespace(
                source=str(source), output=str(output), products_root=str(products),
                target_app=str(app), use_destination_artifacts=True,
                environment=["NVPN_RELEASE_JOIN_BLACKBOX=1"], environment_stdin0=False,
            ))
            actual = xctestrun_targets(plistlib.loads(output.read_bytes()))[0]
            self.assertIs(actual["UseDestinationArtifacts"], True)
            self.assertIs(actual["UseUITargetAppProvidedByTests"], False)
            self.assertEqual(actual["UITargetAppBundleIdentifier"], "example.nvpn")
            self.assertEqual(actual["TestHostBundleIdentifier"], "example.nvpn.UITests.xctrunner")
            self.assertEqual(actual["TestBundleDestinationRelativePath"], "PlugIns/NostrVpnIosUITests.xctest")
            for key in ("TestBundlePath", "TestHostPath", "UITargetAppPath", "DependentProductPaths"):
                self.assertNotIn(key, actual)
            self.assertEqual(actual["UITargetAppCommandLineArguments"], [])
            self.assertEqual(actual["UITargetAppEnvironmentVariables"], {})
            self.assertEqual(actual["EnvironmentVariables"],
                             {"RUNNER_ONLY": "retained", "NVPN_RELEASE_JOIN_BLACKBOX": "1"})
            self.assertEqual(source.read_bytes(), original)
            self.assertEqual({p: p.read_bytes() for p in products_before}, products_before)
            self.assertEqual(plistlib.loads(source.read_bytes()), copy.deepcopy(payload))

    def test_legacy_plan_with_tests_provided_target_flag(self):
        self.check_layout(False)

    def test_modern_plan_with_tests_provided_target_flag(self):
        self.check_layout(True)


if __name__ == "__main__":
    unittest.main()
