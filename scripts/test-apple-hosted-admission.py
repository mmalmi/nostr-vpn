#!/usr/bin/env python3
"""Reject changed or escaping hosted inputs before importing any payload."""

import copy
import hashlib
import io
import plistlib
import shutil
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest

sys.dont_write_bytecode = True
import apple_hosted_admission as hosted


class HostedAdmission(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.archive = self.root / "payload.tar.gz"
        self.output = self.root / "output"
        self.data = b"unchanged compiled payload\n"
        self.files = [{"path": "app/executable", "bytes": len(self.data),
                       "sha256": hashlib.sha256(self.data).hexdigest()}]

    def package(self, name="app/executable", data=None, link=False):
        with tarfile.open(self.archive, "w:gz") as package:
            entry = tarfile.TarInfo(name)
            if link:
                entry.type = tarfile.SYMTYPE
                entry.linkname = "/tmp/unrelated"
                package.addfile(entry)
            else:
                content = self.data if data is None else data
                entry.size = len(content)
                entry.mode = 0o755
                package.addfile(entry, io.BytesIO(content))

    def test_exact_manifest_imports_original_bytes_and_mode(self):
        self.package()
        hosted.checked_tar(self.archive, self.output, self.files)
        self.assertEqual((self.output / "app/executable").read_bytes(), self.data)
        self.assertEqual((self.output / "app/executable").stat().st_mode & 0o777, 0o755)

    def test_changed_missing_and_unlisted_payloads_fail_before_writing(self):
        for name, data in (("app/executable", b"changed bytes"),
                           ("app/other", self.data)):
            with self.subTest(name=name):
                self.package(name, data)
                with self.assertRaises(ValueError):
                    hosted.checked_tar(self.archive, self.output, self.files)
                self.assertFalse(self.output.exists())
        self.package()
        manifest = copy.deepcopy(self.files)
        manifest[0]["sha256"] = "0" * 64
        with self.assertRaises(ValueError):
            hosted.checked_tar(self.archive, self.output, manifest)
        self.assertFalse(self.output.exists())

    def test_links_and_escaping_paths_fail_before_writing(self):
        for name, link in (("../outside", False), ("/absolute", False),
                           ("app/executable", True)):
            with self.subTest(name=name, link=link):
                self.package(name, link=link)
                with self.assertRaises(ValueError):
                    hosted.checked_tar(self.archive, self.output, self.files)
                self.assertFalse(self.output.exists())

    def test_other_producer_failed_run_and_wrong_artifact_are_rejected(self):
        run = {"id": 123, "head_sha": hosted.PRODUCER,
               "repository": {"full_name": hosted.REPOSITORY},
               "path": ".github/workflows/apple-release-inputs.yml",
               "status": "completed", "conclusion": "success", "run_attempt": 1}
        artifact = {"id": 456, "name": f"apple-release-inputs-ios-{hosted.APP['commit']}",
                    "expired": False, "workflow_run": {"id": 123, "head_sha": hosted.PRODUCER},
                    "digest": "sha256:" + "a" * 64, "size_in_bytes": 100}
        job = {"id": 789, "run_id": 123, "run_attempt": 1, "head_sha": hosted.PRODUCER,
               "name": "inputs (ios)", "status": "completed", "conclusion": "success"}
        self.assertEqual(hosted.authenticate_run(run, artifact, job, "ios", 123)["artifactId"], 456)
        for key, value in (("head_sha", "0" * 40),
                           ("path", ".github/workflows/unreviewed.yml")):
            with self.subTest(key=key), self.assertRaises(ValueError):
                hosted.authenticate_run({**run, key: value}, artifact, job, "ios", 123)
        with self.assertRaises(ValueError):
            hosted.authenticate_run(run, {**artifact, "digest": None}, job, "ios", 123)
        for key, value in (("conclusion", "failure"), ("run_attempt", 2)):
            with self.subTest(key=key), self.assertRaises(ValueError):
                hosted.authenticate_run(run, artifact, {**job, key: value}, "ios", 123)

    def test_frozen_hosted_receipt_requires_its_exact_companion(self):
        receipt_path = self.root / "archive-receipt.json"
        hosted.write(receipt_path, {"receiptSchema": 2, "hostedBuildSha256": "a" * 64})
        with self.assertRaises(FileNotFoundError):
            hosted.validate_ios_admission(receipt_path, hosted.load(receipt_path))
        companion = self.root / "hosted-admission.json"
        hosted.write(companion, {"receiptSchema": 1,
            "artifactType": "signed hosted iOS archive admission",
            "archiveReceiptSha256": "0" * 64, "hostedBuild": {}})
        with self.assertRaisesRegex(ValueError, "absent, changed or bound"):
            hosted.validate_ios_admission(receipt_path, hosted.load(receipt_path))
        hosted.write(receipt_path, {"receiptSchema": 1})
        with self.assertRaisesRegex(ValueError, "downgraded"):
            hosted.validate_ios_admission(receipt_path, hosted.load(receipt_path))
        companion.unlink()
        self.assertIsNone(hosted.validate_ios_admission(receipt_path, hosted.load(receipt_path)))

    @unittest.skipUnless(sys.platform == "darwin", "uses the platform's Mach-O signature remover")
    def test_current_executables_and_content_must_match_immutable_inputs(self):
        unsigned, signed = self.root / "unsigned.app", self.root / "signed.app"
        for app in (unsigned, signed):
            for relative, executable in (("", "Nostr VPN"),
                    ("PlugIns/Nostr VPN Tunnel.appex", "Nostr VPN Tunnel"),
                    ("PlugIns/ShareFiles.appex", "ShareFiles")):
                bundle = app / relative
                bundle.mkdir(parents=True)
                shutil.copyfile("/usr/bin/true", bundle / executable)
                (bundle / executable).chmod(0o755)
                (bundle / "Info.plist").write_bytes(plistlib.dumps({
                    "CFBundleIdentifier": "fixture." + executable.replace(" ", ""),
                    "CFBundleShortVersionString": "4.1.21", "CFBundleVersion": "4001031",
                    "NVPNBuildGitSha": hosted.APP["commit"],
                }))
                if app == signed:
                    (bundle / "embedded.mobileprovision").write_bytes(b"fixture profile")
            (app / "asset").write_bytes(b"original content")
        hosted.verify_ios_lineage(unsigned, signed)
        (signed / "asset").write_bytes(b"changed content")
        with self.assertRaises(ValueError):
            hosted.verify_ios_lineage(unsigned, signed)
        (signed / "asset").write_bytes(b"original content")
        for relative in ("Nostr VPN", "PlugIns/Nostr VPN Tunnel.appex/Nostr VPN Tunnel",
                         "PlugIns/ShareFiles.appex/ShareFiles"):
            path = signed / relative
            original = path.read_bytes()
            try:
                path.write_bytes(b"changed executable")
                with self.subTest(executable=relative), self.assertRaises(ValueError):
                    hosted.verify_ios_lineage(unsigned, signed)
            finally:
                path.write_bytes(original)


if __name__ == "__main__":
    unittest.main()
