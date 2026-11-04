#!/usr/bin/env python3
"""Bounded hosted gate-tool fixtures; no compiler, codesign or imported inputs."""

import copy
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
import macos_hosted_support as support
import macos_release_join_artifact as gate
from apple_hosted_admission import digest, write


class HostedSupport(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="nvpn-mac-support-test-")
        self.addCleanup(self.temporary.cleanup)
        self.package = Path(self.temporary.name)
        self.inputs = self.package / "hosted-support"
        self.inputs.mkdir()
        write(self.inputs / "hosted-inputs.json", {"fixture": True})
        for relative in support.SUPPORT_FILES.values():
            for root in (self.package, self.inputs / "unsigned/macos/.build/hosted-gate-support"):
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(relative.encode())
                path.chmod(0o755)
        self.authentication = {**support.SUPPORT_AUTHENTICATION,
            "jobId": 123, "artifactId": 456, "artifactBytes": 789, "artifactSha256": "1" * 64}
        self.proof = {"authentication": copy.deepcopy(self.authentication),
                      "producerReceiptSha256": "2" * 64}
        self.signing = {"team": "TESTTEAM01", "certificateSha1": "3" * 40,
                        "certificateSha256": "4" * 64}
        for manager in (
            patch.object(support, "SUPPORT_AUTHENTICATION", self.authentication),
            patch.object(support, "verified_inputs", return_value=self.proof),
            patch.object(support, "normalized_executable", side_effect=digest),
            patch.object(gate, "inspect_signature", return_value={**self.signing,
                "authority": "Developer ID Application: Test"}),
        ):
            manager.start()
            self.addCleanup(manager.stop)

    def test_support_has_its_own_successful_job_and_artifact(self):
        for key, wrong in (("jobId", 321), ("jobConclusion", "failure"),
                           ("artifactSha256", "0" * 64), ("producerCommit", "0" * 40)):
            original = self.proof["authentication"][key]
            self.proof["authentication"][key] = wrong
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "job/artifact"):
                support.support_evidence(self.package, self.signing)
            self.proof["authentication"][key] = original

    def test_all_four_signed_tools_remain_bound_to_original_hosted_bytes(self):
        evidence = support.support_evidence(self.package, self.signing)
        receipt = {**support.support_receipt_fields(evidence), "signingTeam": self.signing["team"],
                   "signingIdentitySha1": self.signing["certificateSha1"],
                   "signerCertificateSha256": self.signing["certificateSha256"]}
        support.validate_support_receipt(receipt, self.package)
        for relative in support.SUPPORT_FILES.values():
            path = self.package / relative
            before = path.read_bytes()
            path.write_bytes(before + b"changed")
            with self.subTest(tool=relative), self.assertRaisesRegex(ValueError, "hosted compilation"):
                support.validate_support_receipt(receipt, self.package)
            path.write_bytes(before)
        with self.assertRaisesRegex(ValueError, "missing"):
            support.validate_support_receipt({key: value for key, value in receipt.items()
                                              if key != "hostedSupport"}, self.package)
        forged = copy.deepcopy(receipt)
        forged["hostedSupport"]["authentication"]["jobId"] = 321
        forged["hostedSupportCanonicalSha256"] = support.canonical_digest(forged["hostedSupport"])
        with self.assertRaisesRegex(ValueError, "changed"):
            support.validate_support_receipt(forged, self.package)

    def test_symlinks_modes_and_other_signers_are_rejected(self):
        path = self.package / support.SUPPORT_FILES["exitDnsDriverSha256"]
        path.chmod(0o700)
        with self.assertRaisesRegex(ValueError, "mode"):
            support.support_evidence(self.package, self.signing)
        path.chmod(0o755)
        with self.assertRaisesRegex(ValueError, "signing team"):
            support.support_evidence(self.package, {**self.signing, "team": "OTHERTEAM1"})
        path.unlink()
        path.symlink_to(self.package / support.SUPPORT_FILES["manualJoinDriverSha256"])
        with self.assertRaisesRegex(ValueError, "link"):
            support.support_evidence(self.package, self.signing)


if __name__ == "__main__":
    unittest.main()
