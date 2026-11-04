#!/usr/bin/env python3
"""Verify signed VM gate tools against their separately authenticated hosted build."""

import pathlib
import stat

from apple_hosted_admission import canonical_digest, digest, require, verified_inputs
from macos_hosted_admission import normalized_executable


SUPPORT_AUTHENTICATION = {
    "producerCommit": "b940ed359d394e673f287ff5c807b1afac5864e7",
    "runId": "41914639900", "runAttempt": "1",
    "jobName": "inputs (macos-support)", "jobConclusion": "success",
    "jobId": 126870963536, "artifactId": 13364154571, "artifactBytes": 2576315,
    "artifactSha256": "865c60c6ef954f80a22f9ee0e21c3dfe22e77d42a3cdd8cfe75f977c08e01262",
}
SUPPORT_FILES = {
    "manualJoinFixtureSha256": "fixtures/desktop_manual_join_e2e_fixture",
    "manualJoinDriverSha256": "drivers/desktop-manual-join-ax",
    "serviceToggleDriverSha256": "drivers/macos-service-toggle-ax",
    "exitDnsDriverSha256": "drivers/macos-exit-dns-ax",
}


def support_evidence(package, signing):
    from macos_release_join_artifact import inspect_signature, verify_signature
    package = pathlib.Path(package).resolve(strict=True)
    root = package / "hosted-support"
    require(root.is_dir() and not root.is_symlink() and root.resolve().parent == package,
            "hosted support directory must be real and contained in its package")
    proof = verified_inputs(root, "macos-support")
    require(all(proof["authentication"].get(key) == value
                for key, value in SUPPORT_AUTHENTICATION.items()),
            "hosted gate-tool job/artifact differs from admitted producer")
    files = {}
    for relative in SUPPORT_FILES.values():
        signed = package / relative
        unsigned = root / "unsigned/macos/.build/hosted-gate-support" / relative
        require(signed.is_file() and not signed.is_symlink(), "signed gate tool is absent or a link")
        require(stat.S_IMODE(signed.stat().st_mode) == stat.S_IMODE(unsigned.stat().st_mode),
                "gate-tool executable mode changed")
        original = normalized_executable(unsigned)
        require(normalized_executable(signed) == original,
                "signed gate tool differs from hosted compilation")
        signature = inspect_signature(signed)
        verify_signature(signature, expected_team=signing["team"],
                         expected_identity=signing["certificateSha1"],
                         expected_signer=signing["certificateSha256"], label="hosted gate tool")
        files[relative] = {"sha256": digest(signed), "normalizedSha256": original,
                           "mode": stat.S_IMODE(signed.stat().st_mode)}
    return {"receiptSchema": 1, "buildOrigin": "github-actions", "signedOnHost": True,
            "authentication": proof["authentication"], "files": files,
            "inputProofSha256": digest(root / "hosted-inputs.json"),
            "producerReceiptSha256": proof["producerReceiptSha256"]}


def support_receipt_fields(evidence):
    return {"hostedSupport": evidence, "hostedSupportCanonicalSha256": canonical_digest(evidence),
            **{key: evidence["files"][relative]["sha256"] for key, relative in SUPPORT_FILES.items()}}


def validate_support_receipt(receipt, package):
    evidence = support_evidence(package, {"team": receipt["signingTeam"],
        "certificateSha1": receipt["signingIdentitySha1"],
        "certificateSha256": receipt["signerCertificateSha256"]})
    require(all(receipt.get(key) == value for key, value in support_receipt_fields(evidence).items()),
            "hosted gate-tool receipt changed or is missing")
    return evidence
