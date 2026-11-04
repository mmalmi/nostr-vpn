#!/usr/bin/env python3
"""Source-only adversarial Android admission fixtures; no products, keys or builds."""

import base64
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile
from types import SimpleNamespace
import subprocess

sys.dont_write_bytecode = True
import android_hosted_admission as admission
import android_hosted_inputs as inputs
import mobile_release_artifact_receipt as mobile
from android_hosted_content import MANIFEST, canonical_digest, digest


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True) + "\n")


def archive(path, files):
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as package:
        for name, value in files.items():
            package.writestr(name, value)


class AndroidAdmission(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="nvpn-android-admission-fixture-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.hosted = self.root / "hosted"
        self.payload = self.hosted / "payload"
        self.payload.mkdir(parents=True)
        self.signer = "1" * 64
        self.native = {"base/lib/arm64-v8a/libnostr_vpn_app_core.so": b"compiled JNI",
                       "base/dex/classes.dex": b"compiled DEX"}
        unsigned = self.payload / "unsigned/app-release.aab"
        archive(unsigned, self.native)
        jni = self.payload / "unsigned/jni/arm64-v8a/libnostr_vpn_app_core.so"
        jni.parent.mkdir(parents=True)
        jni.write_bytes(b"compiled JNI")
        checkout = "/fixture-hosted-checkout/fips"
        self.metadata = {"checkoutHead": inputs.FIPS["commit"], "checkoutTree": inputs.FIPS["tree"],
            "fipsCoreVersion": inputs.FIPS_VERSION, "checkoutPathSha256": hashlib.sha256(checkout.encode()).hexdigest(),
            "source": "exact clean local Cargo path dependency"}
        save(self.payload / "provenance/fips-linkage.json", self.metadata)
        for name, value in {"committed-Cargo.lock": b"committed\n", "realized-Cargo.lock": b"realized\n",
                "forced-rebuild.marker": b"", "dep-info/fips_core-fixture.d":
                ("target: " + checkout + "/crates/fips-core/src/lib.rs\n").encode(),
                "build.sh": b"canonical helper recipe", "build-environment.json": b"{}\n"}.items():
            path = self.payload / "provenance" / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(value)
        for name, value in (("COMMITTED_LOCK", hashlib.sha256(b"committed\n").hexdigest()),
                            ("REALIZED_LOCK", hashlib.sha256(b"realized\n").hexdigest())):
            manager = patch.object(inputs, name, value)
            manager.start()
            self.addCleanup(manager.stop)
        save(self.payload / "provenance/inputs.json", {"app": inputs.APP,
            "fips": {**inputs.FIPS, "version": inputs.FIPS_VERSION}, "target": "aarch64-linux-android",
            "abi": "arm64-v8a", "realizedCargoLockSha256": inputs.REALIZED_LOCK,
            "hostedNativeComponentsQualified": True})
        save(self.payload / "provenance/resources.json", {"abortReason": None, "commands": [{"exitCode": 0}]})
        self.service = {**inputs.SERVICE, "runAttempt": "1", "jobId": 123, "artifactId": 456,
                        "artifactBytes": 1, "artifactSha256": "2" * 64}
        manager = patch.object(inputs, "SERVICE", self.service)
        manager.start()
        self.addCleanup(manager.stop)
        record = lambda path: {"sha256": digest(path), "size": path.stat().st_size, "originalMtimeNs": 1000}
        self.receipt = {"schema": 1, "platform": "android", "configuration": "Release",
            "source": {"app": inputs.APP, "fips": inputs.FIPS}, "canonicalScripts": inputs.SCRIPTS,
            "distributionSigned": False, "runtimeTestsExecuted": False, "releaseAccepted": False,
            "signingInputsAbsent": True, "signed": False, "buildExitCode": 0, "imageVersion": "fixture",
            "toolVersions": {"rustc": "rustc 1.95.0 (59807616e 2026-04-14)"},
            "rust": {"target": "aarch64-linux-android", "package": "nostr-vpn-app-core",
                     "profile": "release", "defaultFeatures": True, "additionalFeatures": []},
            "producer": {"commit": self.service["producerCommit"], "runId": self.service["runId"],
                         "attempt": "1", "job": "inputs", "repository": self.service["repository"]},
            "forcedRebuild": record(self.payload / "provenance/forced-rebuild.marker"),
            "compiledJni": record(jni), "fipsCheckoutPathSha256": self.metadata["checkoutPathSha256"],
            "jniPayloads": {"base/lib/arm64-v8a/libnostr_vpn_app_core.so": {
                "sha256": digest(jni), "size": jni.stat().st_size, "origin": "unsigned AAB entry", "zipDateTime": []}},
            "files": {path.relative_to(self.payload).as_posix(): record(path)
                      for path in self.payload.rglob("*") if path.is_file()}}
        save(self.payload / "provenance/receipt.json", self.receipt)
        package = self.hosted / "github-artifact.zip"
        archive(package, {path.relative_to(self.payload).as_posix(): path.read_bytes()
                          for path in self.payload.rglob("*") if path.is_file()})
        self.service.update(artifactBytes=package.stat().st_size, artifactSha256=digest(package))
        proof = inputs.verified_inputs(self.hosted, self.service)
        save(self.hosted / "hosted-inputs.json", {"receiptSchema": 1, "platform": "android", **proof})

    def test_successful_service_job_attempt_and_artifact_are_required(self):
        run = {"id": int(self.service["runId"]), "head_sha": self.service["producerCommit"],
               "path": self.service["workflow"], "repository": {"full_name": self.service["repository"]}, "run_attempt": 1}
        job = {"id": 123, "run_id": run["id"], "run_attempt": 1, "head_sha": run["head_sha"],
               "name": "inputs", "status": "completed", "conclusion": "success"}
        artifact = {"id": 456, "name": self.service["artifactName"], "size_in_bytes": self.service["artifactBytes"],
            "expired": False, "digest": "sha256:" + self.service["artifactSha256"],
            "workflow_run": {"id": run["id"], "head_sha": run["head_sha"]}}
        inputs.authenticate_service(run, job, artifact)
        for field, value in (("id", 999), ("run_attempt", 2), ("conclusion", "failure")):
            with self.subTest(field=field), self.assertRaises(ValueError):
                inputs.authenticate_service(run, {**job, field: value}, artifact)
        with self.assertRaises(ValueError):
            inputs.authenticate_service(run, job, {**artifact, "digest": "sha256:" + "0" * 64})

    def test_retained_service_evidence_and_real_input_directory_cannot_be_replaced(self):
        inputs.verified_inputs(self.hosted)
        path = self.payload / "provenance/fips-linkage.json"
        original = path.read_bytes()
        save(path, {**self.metadata, "checkoutPathSha256": "0" * 64})
        with self.assertRaisesRegex(ValueError, "service ZIP"):
            inputs.verified_inputs(self.hosted)
        path.write_bytes(original)
        linked = self.root / "linked"
        linked.symlink_to(self.hosted, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "root must be real"):
            inputs.verified_inputs(linked)

    def test_original_target_recipe_and_rebuild_times_are_checked(self):
        for change in ({"rust": {**self.receipt["rust"], "defaultFeatures": False}},
                       {"canonicalScripts": {}}, {"compiledJni": {**self.receipt["compiledJni"], "originalMtimeNs": 999}}):
            with self.subTest(change=list(change)), self.assertRaises(ValueError):
                inputs.validate_producer({**self.receipt, **change}, self.payload)

    def test_mobile_validator_preserves_local_default_and_requires_hosted_evidence(self):
        apk = self.payload / "unsigned/app-release.aab"
        metadata = self.payload / "provenance/fips-linkage.json"
        path = self.root / "physical-receipt.json"
        receipt = {"receiptSchema": 2, "artifactType": "Android Release APK",
            "apkSha256": digest(apk), "installedApkSha256": digest(apk), "companySigningVerified": True,
            "signerCertificateSha256": self.signer, "appGitSha": inputs.APP["commit"], "appGitTree": inputs.APP["tree"],
            "fipsGitSha": inputs.FIPS["commit"], "fipsGitTree": inputs.FIPS["tree"], "fipsCoreVersion": inputs.FIPS_VERSION,
            "fipsCargoMetadataReceiptSha256": digest(metadata), "fipsDependenciesForcedRebuilt": True,
            "package": "fi.siriusbusiness.nvpn", "replacementInstall": True, "debuggable": False,
            "apkPathSha256": admission.path_digest(apk), "fipsCheckoutPathSha256": self.metadata["checkoutPathSha256"],
            "fipsCargoMetadataReceiptPathSha256": admission.path_digest(metadata)}
        save(path, receipt)
        args = SimpleNamespace(receipt=str(path), apk=str(apk), fips_metadata=str(metadata),
            app_root=str(self.root / "app"), fips_root=str(self.root / "fips"), signer_sha=self.signer,
            app_head=inputs.APP["commit"], app_tree=inputs.APP["tree"], fips_head=inputs.FIPS["commit"],
            fips_tree=inputs.FIPS["tree"], fips_version=inputs.FIPS_VERSION,
            package="fi.siriusbusiness.nvpn", actual_package="fi.siriusbusiness.nvpn")
        mobile.validate_android(args)
        save(path, {**receipt, "buildOrigin": "github-actions"})
        with self.assertRaisesRegex(ValueError, "requires its exact AAB"):
            mobile.validate_android(args)

    def test_hosted_gate_refuses_local_compilation_before_other_operations(self):
        script = Path(__file__).with_name("lib-mobile-android-release-gate.sh")
        result = subprocess.run(["bash", "-c", 'set -eu; source "$1"; build=1; '
            'NVPN_ANDROID_HOSTED_ADMISSION=fixture; android_release_require_inputs', "fixture", str(script)],
            capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("local compilation is disabled", result.stderr)

    def test_admission_rejects_payload_substitution_and_retagged_historical_metadata(self):
        manifest = "Manifest-Version: 1.0\r\n\r\n"
        for name, value in self.native.items():
            manifest += "Name: " + name + "\r\nSHA-256-Digest: " + base64.b64encode(hashlib.sha256(value).digest()).decode() + "\r\n\r\n"
        aab, apk = self.root / "signed.aab", self.root / "derived.apk"
        archive(aab, {**self.native, MANIFEST: manifest.encode(), "META-INF/TEST.SF": b"fixture", "META-INF/TEST.RSA": b"fixture"})
        apk_files = {"lib/arm64-v8a/libnostr_vpn_app_core.so": b"compiled JNI", "classes.dex": b"compiled DEX"}
        archive(apk, apk_files)
        bundle_path = self.root / "derivation.json"
        bundle = {"schema": 1, "relationship": "universal-apk-derived-from-exact-aab",
            "appGitSha": inputs.APP["commit"], "appGitTree": inputs.APP["tree"],
            "aabSha256": digest(aab), "apkSha256": digest(apk), "aabPathSha256": admission.path_digest(aab),
            "apkPathSha256": admission.path_digest(apk), "bundletoolVersion": "1.18.3", "bundletoolSha256": inputs.BUNDLETOOL_SHA}
        save(bundle_path, bundle)
        local_path = self.root / "local-validation.json"
        save(local_path, {"local": True})
        local = {"metadata": {"checkoutPathSha256": "a" * 64}, "metadataSha256": digest(local_path)}
        companion = self.root / "android-hosted-admission.json"
        value = {"receiptSchema": 1, "artifactType": admission.TYPE, "contentContract": admission.CONTRACT,
                 "inputDirectory": "hosted", "localValidationFile": local_path.name, "signerCertificateSha256": self.signer}
        with patch.object(admission, "local_validation", return_value=local), \
                patch.object(admission, "verify_aab_signer"), patch.object(admission, "verify_apk_signer"):
            value.update(admission.observe(companion, value, aab, apk, bundle_path, self.root, self.root))
            save(companion, value)
            admission.validate_admission(companion, aab, apk, bundle_path, self.root, self.root, self.signer)
            physical = admission.receipt_fields(companion, value)
            historical = self.payload / "provenance/fips-linkage.json"
            admission.validate_physical_receipt(physical, companion, aab, apk, bundle_path,
                                               historical, self.root, self.root, self.signer)
            with self.assertRaisesRegex(ValueError, "exact hosted admission"):
                admission.validate_physical_receipt({}, companion, aab, apk, bundle_path,
                                                   historical, self.root, self.root, self.signer)
            retagged = self.root / "retagged.json"
            retagged.write_text(json.dumps(self.metadata, indent=4))
            with self.assertRaisesRegex(ValueError, "retagged"):
                admission.validate_physical_receipt(physical, companion, aab, apk, bundle_path,
                                                   retagged, self.root, self.root, self.signer)
            archive(apk, {**apk_files, "classes.dex": b"different application"})
            save(bundle_path, {**bundle, "apkSha256": digest(apk)})
            with self.assertRaisesRegex(ValueError, "runtime bytes"):
                admission.validate_admission(companion, aab, apk, bundle_path, self.root, self.root, self.signer)
        companion.unlink()
        with self.assertRaisesRegex(ValueError, "absent"):
            admission.validate_admission(companion, aab, apk, bundle_path, self.root, self.root, self.signer)


if __name__ == "__main__":
    unittest.main()
