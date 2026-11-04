#!/usr/bin/env python3
"""Small artifact fixtures: no compilation, signing, network or imported products."""

import copy
import hashlib
import os
from pathlib import Path
import plistlib
import shutil
import sys
import subprocess
import struct
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

sys.dont_write_bytecode = True
import macos_hosted_admission as mac
REAL_NORMALIZER = mac.normalized_executable


class HostedMacAdmission(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="nvpn-macos-admission-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.unsigned = self.root / "unsigned.app"
        self.signed = self.root / "signed.app"
        for app, group in ((self.unsigned, mac.UNSIGNED_GROUP),
                           (self.signed, "ABCDEFGHIJ.fi.siriusbusiness.nvpn.shared")):
            for name in mac.EXECUTABLES.values():
                path = app / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes((name + " compiled payload").encode())
                path.chmod(0o755)
            for name in mac.GROUP_PLISTS:
                path = app / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(plistlib.dumps({"NVPNShareAppGroup": group,
                    "CFBundleVersion": "421", "NVPNBuildGitSha": mac.APP["commit"]}))
            resource = app / "Contents/Resources/privacy.json"
            resource.write_bytes(b'{"unchanged":true}')
        self.group = "ABCDEFGHIJ.fi.siriusbusiness.nvpn.shared"
        # Fixture executables model already-normalized linker bytes. Production
        # normalization is deliberately never run on a user's signed product.
        self.normalizer = patch.object(mac, "normalized_executable", side_effect=mac.digest)
        self.normalizer.start()
        self.addCleanup(self.normalizer.stop)

    def test_only_expected_group_and_signature_files_may_differ(self):
        signature = self.signed / "Contents/_CodeSignature/CodeResources"
        signature.parent.mkdir(parents=True)
        signature.write_bytes(b"private signing envelope")
        self.assertEqual(mac.content_identity(self.unsigned, mac.UNSIGNED_GROUP),
                         mac.content_identity(self.signed, self.group))
        path = self.signed / mac.GROUP_PLISTS[0]
        data = plistlib.loads(path.read_bytes())
        data["CFBundleVersion"] = "422"
        path.write_bytes(plistlib.dumps(data))
        self.assertNotEqual(mac.content_identity(self.unsigned, mac.UNSIGNED_GROUP),
                            mac.content_identity(self.signed, self.group))

    def test_each_executable_resource_mode_and_extra_file_are_bound(self):
        original = mac.content_identity(self.signed, self.group)
        for relative in (*mac.EXECUTABLES.values(), "Contents/Resources/privacy.json"):
            path = self.signed / relative
            before = path.read_bytes()
            path.write_bytes(before + b" changed")
            self.assertNotEqual(mac.content_identity(self.signed, self.group), original)
            path.write_bytes(before)
        executable = self.signed / next(iter(mac.EXECUTABLES.values()))
        executable.chmod(0o700)
        self.assertNotEqual(mac.content_identity(self.signed, self.group), original)
        executable.chmod(0o755)
        (self.signed / "Contents/Resources/extra").write_bytes(b"extra")
        self.assertNotEqual(mac.content_identity(self.signed, self.group), original)

    def test_wrong_group_and_symlinks_are_rejected(self):
        with self.assertRaises(ValueError):
            mac.content_identity(self.signed, "WRONG.group")
        (self.signed / "Contents/Resources/link").symlink_to("/tmp")
        with self.assertRaises(ValueError):
            mac.content_identity(self.signed, self.group)

    def test_only_a_verified_staple_ticket_may_change_after_gating(self):
        signature = self.signed / "Contents/_CodeSignature/CodeResources"
        signature.parent.mkdir()
        signature.write_bytes(b"sealed signing envelope")
        admission = {"normalization": mac.NORMALIZATION,
                     "appIdentity": mac.signed_identity(self.signed),
                     "contentIdentity": mac.content_identity(self.signed, self.group),
                     "signedAppGroup": self.group}
        self.assertEqual(mac.unstapled_tree_sha256(self.signed), mac.tree_sha256(self.signed))
        ticket = self.signed / mac.STAPLE_TICKET
        ticket.write_bytes(b"Apple staple ticket")
        with self.assertRaises(ValueError):
            mac.assert_current_app(admission, self.signed)
        with patch.object(mac.subprocess, "run", side_effect=subprocess.CalledProcessError(1, "stapler")):
            with self.assertRaises(subprocess.CalledProcessError):
                mac.assert_current_app(admission, self.signed, allow_stapled=True)
        with patch.object(mac.subprocess, "run") as validate:
            mac.assert_current_app(admission, self.signed, allow_stapled=True)
            validate.assert_called_once_with(["xcrun", "stapler", "validate", str(self.signed)],
                check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            signature.write_bytes(b"changed signing envelope")
            with self.assertRaises(ValueError):
                mac.assert_current_app(admission, self.signed, allow_stapled=True)
            signature.write_bytes(b"sealed signing envelope")
            ticket.unlink()
            ticket.symlink_to(signature)
            with self.assertRaises(ValueError):
                mac.assert_current_app(admission, self.signed, allow_stapled=True)

    def test_host_scratch_cannot_breach_twenty_gib_reserve(self):
        with patch.dict(os.environ, {}, clear=True), \
                patch.object(mac.shutil, "disk_usage", return_value=SimpleNamespace(free=mac.HOST_RESERVE)):
            with self.assertRaisesRegex(ValueError, "scratch reserve"):
                mac.comparison_scratch(113329624)

    def test_normalization_pipeline_uses_validated_allocation_without_mutating_inputs(self):
        hashes = []
        for index, (signature_size, payload) in enumerate(((32, b"payload!" * 9),
                (20000, b"payload!" * 9), (20000, b"changed!" * 9))):
            allocation = (len(payload) + signature_size + 16383) // 16384 * 16384
            header = lambda count, size: struct.pack("<8I", 0xFEEDFACF, 0x0100000C, 0, 2, count, size, 0, 0)
            segment = lambda size: struct.pack("<II16s4Q4I", 0x19, 72, b"__LINKEDIT", 0x100004000,
                                               allocation, 120, size, 1, 1, 0, 0)
            original = self.root / f"signature-{index}"
            original.write_bytes(header(2, 88) + segment(len(payload) + signature_size)
                + struct.pack("<4I", 0x1D, 16, 120 + len(payload), signature_size)
                + payload + b"s" * signature_size)
            before = mac.digest(original)
            def stripped_copy(command, **kwargs):
                self.assertEqual(command[:2], ["codesign", "--remove-signature"])
                Path(command[2]).write_bytes(header(1, 72) + segment(len(payload)) + b"\0" * 16 + payload)
            with patch.object(mac, "comparison_scratch", return_value=self.root), \
                    patch.object(mac.subprocess, "run", side_effect=stripped_copy):
                hashes.append(REAL_NORMALIZER(original))
            self.assertEqual(mac.digest(original), before)
        self.assertEqual(hashes[0], hashes[1])
        self.assertNotEqual(hashes[0], hashes[2])

    def test_ram_scratch_requires_exact_volume_growth_and_remaining_reserve(self):
        contract_path = self.root / "scratch-admission.json"
        scratch = self.root / "comparison"
        scratch.mkdir()
        contract = {"receiptSchema": 1, "storageKind": "ram-disk", "directory": str(scratch),
                    "mountPoint": str(self.root), "volumeUuid": "TEST-VOLUME-UUID",
                    "reserveBytes": mac.RAM_RESERVE, "maximumGrowthBytes": 256 * 1024**2}
        mac.write(contract_path, contract)
        disk_info = {"VolumeUUID": contract["volumeUuid"], "MountPoint": str(self.root),
                     "DeviceNode": "/dev/test-ram"}
        images = {"images": [{"image-path": "ram://2097152", "system-entities": [
            {"dev-entry": "/dev/test-ram", "mount-point": str(self.root)}]}]}
        original_stat = Path.stat
        nested_device = False
        def separate_volume(path, *args, **kwargs):
            result = original_stat(path, *args, **kwargs)
            if path in (self.root, scratch):
                values = list(result)
                values[2] += 2 if nested_device and path == scratch else 1
                return os.stat_result(values)
            return result
        def volume_info(command):
            if command[0] == "diskutil":
                self.assertEqual(command, ["diskutil", "info", "-plist", str(self.root)])
            return plistlib.dumps(disk_info if command[0] == "diskutil" else images)
        growth = 2 * 113329624 + 1024**2
        with patch.dict(os.environ, {mac.SCRATCH_ADMISSION_ENV: str(contract_path)}), \
                patch.object(Path, "stat", autospec=True, side_effect=separate_volume), \
                patch.object(mac.subprocess, "check_output", side_effect=volume_info), \
                patch.object(mac.shutil, "disk_usage", return_value=SimpleNamespace(free=mac.RAM_RESERVE + growth)) as usage:
            self.assertEqual(mac.comparison_scratch(113329624), scratch)
            nested_device = True
            with self.assertRaisesRegex(ValueError, "volume identity"):
                mac.comparison_scratch(113329624)
            nested_device = False
            disk_info["VolumeUUID"] = "REPLACED-VOLUME"
            with self.assertRaisesRegex(ValueError, "volume identity"):
                mac.comparison_scratch(113329624)
            disk_info["VolumeUUID"] = contract["volumeUuid"]
            usage.return_value = SimpleNamespace(free=mac.RAM_RESERVE + growth - 1)
            with self.assertRaisesRegex(ValueError, "scratch reserve"):
                mac.comparison_scratch(113329624)
            usage.return_value = SimpleNamespace(free=mac.RAM_RESERVE + growth)
            with self.assertRaisesRegex(ValueError, "growth budget"):
                mac.comparison_scratch(256 * 1024**2)
            images["images"][0]["image-path"] = "/ordinary/disk-image.dmg"
            with self.assertRaisesRegex(ValueError, "RAM device"):
                mac.comparison_scratch(113329624)

    def test_exact_job_source_recipe_and_lock_are_required(self):
        proof = {"authentication": {**mac.AUTHENTICATION, "runAttempt": "1"},
                 "producerReceipt": {"app": mac.APP, "fips": mac.FIPS,
                    "committedLockSha256": mac.COMMITTED_LOCK,
                    "realizedLockSha256": mac.REALIZED_LOCK,
                    "recipes": mac.RECIPES}}
        mac.validate_build_proof(proof)
        for section, key, value in (
            ("authentication", "jobId", 126826755387),
            ("authentication", "jobConclusion", "failure"),
            ("authentication", "artifactSha256", "0" * 64),
            ("producerReceipt", "app", {**mac.APP, "tree": "0" * 40}),
            ("producerReceipt", "fips", {**mac.FIPS, "commit": "0" * 40}),
            ("producerReceipt", "realizedLockSha256", "0" * 64),
            ("producerReceipt", "recipes", [["cargo", "build"]]),
        ):
            changed = copy.deepcopy(proof)
            changed[section][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                mac.validate_build_proof(changed)

    def test_missing_changed_and_rebound_companions_fail(self):
        companion = self.root / "hosted-admission.json"
        receipt = {"receiptSchema": 2, "buildOrigin": "github-actions",
                   "builtOnHost": False, "builtOnTestVm": False, "signedOnHost": True}
        with self.assertRaises((ValueError, FileNotFoundError)):
            mac.validate_receipt_admission(receipt, companion, self.signed)
        admission = {"receiptSchema": 1, "artifactType": mac.ARTIFACT_TYPE,
                     "inputDirectory": "hosted",
                     "normalization": mac.NORMALIZATION,
                     "appIdentity": mac.signed_identity(self.signed),
                     "signing": {"team": "ABCDEFGHIJ", "certificateSha1": "1" * 40,
                                 "certificateSha256": "2" * 64},
                     "contentIdentity": mac.content_identity(self.signed, self.group),
                     "signedAppGroup": self.group}
        hosted = self.root / "hosted"
        hosted.mkdir()
        mac.write(hosted / "hosted-inputs.json", {"fixture": True})
        shutil.copytree(self.unsigned, hosted / "unsigned" / mac.UNSIGNED_APP)
        proof = {"authentication": {**mac.AUTHENTICATION, "runAttempt": "1"},
                 "producerReceiptSha256": "3" * 64,
                 "producerReceipt": {"app": mac.APP, "fips": mac.FIPS,
                     "committedLockSha256": mac.COMMITTED_LOCK,
                     "realizedLockSha256": mac.REALIZED_LOCK, "recipes": mac.RECIPES}}
        admission.update(authentication=proof["authentication"],
                         producerReceiptSha256=proof["producerReceiptSha256"],
                         inputProofSha256=mac.digest(hosted / "hosted-inputs.json"),
                         buildContract=mac.BUILD_CONTRACT)
        mac.write(companion, admission)
        receipt.update(mac.receipt_fields(companion, admission))
        receipt.update(admission["appIdentity"])
        receipt.update(signingTeam="ABCDEFGHIJ", signingIdentitySha1="1" * 40,
                       signerCertificateSha256="2" * 64)
        receipt.update(appGitSha=mac.APP["commit"], appGitTree=mac.APP["tree"],
                       fipsGitSha=mac.FIPS["commit"], fipsGitTree=mac.FIPS["tree"],
                       fipsCoreVersion="0.4.117")
        # The shared service loader and Apple signature tools are trust
        # boundaries. Exercise the complete Mac admission on real file trees.
        with patch.object(mac, "verified_inputs", return_value=proof), \
                patch.object(mac, "inspect_signing", return_value=self.group):
            mac.validate_receipt_admission(receipt, companion, self.signed)
            with self.assertRaisesRegex(ValueError, "receipt source"):
                mac.validate_receipt_admission({**receipt, "appGitSha": "0" * 40}, companion, self.signed)
            path = self.signed / mac.EXECUTABLES["cliExecutableSha256"]
            path.write_bytes(b"different signed CLI")
            receipt.update(mac.signed_identity(self.signed))
            with self.assertRaises(ValueError):
                mac.validate_receipt_admission(receipt, companion, self.signed)
            rebound = {**admission, "appIdentity": mac.signed_identity(self.signed),
                       "contentIdentity": mac.content_identity(self.signed, self.group)}
            mac.write(companion, rebound)
            receipt.update(mac.receipt_fields(companion, rebound))
            with self.assertRaisesRegex(ValueError, "original hosted bytes"):
                mac.validate_receipt_admission(receipt, companion, self.signed)
            changed = {**admission, "signedAppGroup": "OTHER.group"}
            mac.write(companion, changed)
            with self.assertRaises(ValueError):
                mac.validate_receipt_admission(receipt, companion, self.signed)
        with self.assertRaises(ValueError):
            mac.validate_receipt_admission({**receipt, "receiptSchema": 1}, companion, self.signed)


if __name__ == "__main__":
    unittest.main()
