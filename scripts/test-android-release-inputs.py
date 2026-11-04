#!/usr/bin/env python3
"""Exercise resource and signing boundaries without starting any build tool."""
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET
import zipfile

spec = importlib.util.spec_from_file_location(
    "android_inputs", Path(__file__).with_name("build-android-release-inputs.py"))
producer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(producer)


class AndroidInputBoundary(unittest.TestCase):
    def test_growth_is_additional_to_physical_reserve(self):
        capacity = {"physicalFloorBytes": 20 * 1024**3,
                    "maximumOwnGrowthBudgetBytes": 16 * 1024**3,
                    "concurrentGrowthBudgetBytes": 2 * 1024**3}
        self.assertEqual(producer.required_free_bytes(capacity), 38 * 1024**3)

    def test_lower_floor_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "20 GiB"):
            producer.required_free_bytes({"physicalFloorBytes": 8 * 1024**3,
                                          "maximumOwnGrowthBudgetBytes": 16 * 1024**3,
                                          "concurrentGrowthBudgetBytes": 0})

    def test_each_signing_input_is_rejected_individually(self):
        for name in producer.SIGNING_VARIABLES:
            with self.subTest(variable=name), self.assertRaisesRegex(ValueError, "signing credentials"):
                producer.unsigned_environment({name: "fixture-not-a-key"})
        producer.unsigned_environment({})

    def test_all_committed_dependency_inputs_are_exact_and_metadata_is_verified(self):
        pins = json.loads(producer.PINS.read_text())
        tree = ET.fromstring(producer.verification_xml(pins))
        ns = {"v": "https://schema.gradle.org/dependency-verification"}
        self.assertEqual(tree.findtext("v:configuration/v:verify-metadata", namespaces=ns), "true")
        self.assertGreater(len(tree.findall("v:components/v:component", ns)), 0)
        self.assertFalse(tree.findall(".//v:trusted-artifacts", ns))
        self.assertFalse(tree.findall(".//v:ignored-keys", ns))

    def test_ambiguous_dependency_checksum_is_rejected(self):
        artifact = {"name": "plugin.jar", "sha256": "1" * 64}
        pins = {"gradleVerification": {"components": [{"group": "public", "name": "plugin", "version": "1",
                                                     "artifacts": [artifact, artifact]}]}}
        with self.assertRaisesRegex(ValueError, "ambiguous"):
            producer.verification_xml(pins)

    def bundle(self, extra=None):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as package:
            package.writestr("base/lib/arm64-v8a/libnostr_vpn_app_core.so", b"fixture")
            if extra:
                package.writestr(extra, b"fixture")
        stream.seek(0)
        return zipfile.ZipFile(stream)

    def test_unsigned_jni_entries_are_retained(self):
        with self.bundle("base/lib/arm64-v8a/libdependency.so") as package:
            self.assertEqual(len(producer.bundle_native_entries(package, "arm64-v8a")), 2)

    def test_signed_bundle_and_unqualified_native_payloads_are_rejected(self):
        for name in ("META-INF/SIGNER.RSA", "base/lib/x86_64/libother.so", "base/lib/arm64-v8a/../other.so"):
            with self.subTest(name=name), self.bundle(name) as package, self.assertRaises(ValueError):
                producer.bundle_native_entries(package, "arm64-v8a")

    def test_binary_download_stdout_is_not_mixed_with_diagnostics(self):
        with tempfile.TemporaryDirectory(dir=os.environ["RUNNER_TEMP"]) as temporary:
            root = Path(temporary)
            pins = {"capacity": {"physicalFloorBytes": 20 * 1024**3,
                    "maximumOwnGrowthBudgetBytes": 128 * 1024**2, "concurrentGrowthBudgetBytes": 0}}
            session = producer.BuildSession(root, pins)
            target = root / "download.zip"
            session.run([sys.executable, "-c",
                         "import os;os.write(1,b'PK\\x00\\x01fixture');os.write(2,b'diagnostic\\n')"],
                        stdout_path=target)
            self.assertEqual(target.read_bytes(), b"PK\x00\x01fixture")
            self.assertEqual((root / "build.log").read_text(), "diagnostic\n")


if __name__ == "__main__":
    unittest.main()
