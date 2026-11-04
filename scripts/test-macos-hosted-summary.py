#!/usr/bin/env python3
"""Exercise the actual join-summary block with small validated receipt fixtures."""

import copy
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
import macos_hosted_admission as app
import macos_hosted_support as support


ROOT = Path(__file__).resolve().parents[1]
blocks = re.findall(r"<<'PY'\n(.*?)\nPY",
                    (ROOT / "scripts/macos-vm-release-mobile-join-e2e.sh").read_text(), re.S)
SUMMARY = next(block for block in blocks if "all_timings = {" in block)


class HostedSummary(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="nvpn-macos-summary-fixture-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.harness = "a" * 40
        self.tree = "b" * 40
        self.receipt = {"receiptSchema": 1, "builtOnHost": True, "builtOnTestVm": False,
            "artifactType": "macOS company Developer ID Release gate package",
            "configuration": "Release", "companySigningVerified": True,
            "appGitSha": app.APP["commit"], "appGitTree": app.APP["tree"],
            "fipsGitSha": app.FIPS["commit"], "fipsGitTree": app.FIPS["tree"],
            "signingTeam": "TESTTEAM01", "signingIdentitySha1": "1" * 40,
            "signerCertificateSha256": "2" * 64,
            "componentInputProof": {"candidate_app_git_sha": self.harness,
                                    "candidate_app_git_tree": self.tree},
            **{key: "3" * 64 for key in ("appBundleTreeSha256", *app.EXECUTABLES)}}
        (self.root / "timings.tsv").write_text(
            "macOS-admin-to-Android-manual\t100\nAndroid-admin-to-macOS-manual\t100\n")
        android = {"receiptSchema": 2, "artifactType": "Android Release APK",
            **{key: "4" * 64 for key in ("appGitSha", "appGitTree", "fipsGitSha", "fipsGitTree",
                "apkSha256", "installedApkSha256", "package", "signerCertificateSha256")}}
        app.write(self.root / "android.json", android)

    def hosted(self):
        receipt = copy.deepcopy(self.receipt)
        admission = {"receiptSchema": 1, "artifactType": app.ARTIFACT_TYPE,
            "normalization": app.NORMALIZATION,
            "authentication": {**app.AUTHENTICATION, "runAttempt": "1"},
            "buildContract": app.BUILD_CONTRACT,
            "appIdentity": {key: receipt[key] for key in ("appBundleTreeSha256", *app.EXECUTABLES)},
            "signing": {"team": receipt["signingTeam"],
                        "certificateSha1": receipt["signingIdentitySha1"],
                        "certificateSha256": receipt["signerCertificateSha256"]}}
        companion = self.root / "hosted-admission.json"
        app.write(companion, admission)
        receipt.update(app.receipt_fields(companion, admission))
        evidence = {"receiptSchema": 1, "buildOrigin": "github-actions", "signedOnHost": True,
            "authentication": support.SUPPORT_AUTHENTICATION,
            "files": {path: {"sha256": "5" * 64} for path in support.SUPPORT_FILES.values()}}
        receipt.update(support.support_receipt_fields(evidence))
        return receipt

    def run_summary(self, receipt, *, verified=True):
        path = self.root / "artifact.json"
        app.write(path, receipt)
        app.write(self.root / "verification.json", {"receiptSchema": 1,
            "remoteImportVerified": True,
            "artifactReceiptSha256": app.digest(path) if verified else "0" * 64})
        completed = subprocess.run([sys.executable, "-B", "-c", SUMMARY,
            str(self.root / "summary.json"), str(self.root / "timings.tsv"), str(path), "",
            "0", "0", self.harness, self.tree, str(self.root / "android.json"),
            str(self.root / "android.json"), "pixel", "", str(ROOT),
            str(self.root / "verification.json")], capture_output=True, text=True)
        return completed

    def test_validated_local_and_hosted_summaries_preserve_origin(self):
        for receipt in (self.receipt, self.hosted()):
            with self.subTest(schema=receipt["receiptSchema"]):
                result = self.run_summary(receipt)
                self.assertEqual(result.returncode, 0, result.stderr)
                summary = json.loads((self.root / "summary.json").read_text())
                self.assertEqual(summary["builtOnHost"], receipt["builtOnHost"])
                if receipt["receiptSchema"] == 2:
                    self.assertEqual(summary["buildOrigin"], "github-actions")
                    self.assertEqual(summary["hostedAdmissionReceiptSha256"], receipt["hostedAdmissionReceiptSha256"])

    def test_unknown_forged_unverified_and_wrong_source_receipts_fail(self):
        unsupported = {**self.receipt, "receiptSchema": 3}
        wrong_source = self.hosted()
        wrong_source["componentInputProof"]["candidate_app_git_sha"] = "0" * 40
        forged = self.hosted()
        forged["hostedAdmission"]["authentication"]["jobId"] += 1
        forged["hostedAdmissionCanonicalSha256"] = app.canonical_digest(forged["hostedAdmission"])
        missing = self.hosted()
        del missing["hostedAdmission"]
        for receipt in (unsupported, wrong_source, forged, missing):
            with self.subTest(receipt=receipt.get("receiptSchema")):
                self.assertNotEqual(self.run_summary(receipt).returncode, 0)
        self.assertNotEqual(self.run_summary(self.hosted(), verified=False).returncode, 0)


if __name__ == "__main__":
    unittest.main()
