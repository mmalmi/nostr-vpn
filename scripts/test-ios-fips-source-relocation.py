#!/usr/bin/env python3
"""Exercise frozen source relocation with real clean Git fixtures, no builds."""
import contextlib
import copy
import io
import json
import os
import pathlib
import re
import shutil
import subprocess
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import ios_frozen_archive as frozen


class SourceRelocationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="ios-fips-relocation-")
        self.addCleanup(self.temporary.cleanup)
        self.root = pathlib.Path(self.temporary.name)
        self.source = self.repository("application")
        self.fips = self.repository("fips-original")
        self.metadata = self.root / "fips-metadata.json"
        self.archive = self.root / "app.xcarchive"
        self.app = frozen.archive_app(self.archive)
        self.app.mkdir(parents=True)
        (self.app / "payload").write_bytes(b"unchanged application bytes")
        self.receipt_path = self.root / "archive-receipt.json"
        self.identity = {"fixtureIdentity": "original"}
        self.signing = {"fixtureSignature": "original"}
        app_head, app_tree = frozen.source_revision(self.source)
        head, tree = frozen.source_revision(self.fips)
        self.args = SimpleNamespace(
            source_root=str(self.source), fips_root=str(self.fips),
            app_head=app_head, app_tree=app_tree, fips_head=head, fips_tree=tree,
            fips_version="1.2.3", fips_metadata=str(self.metadata),
            rust_profile="release", archive=str(self.archive),
            archive_receipt=str(self.receipt_path), version="4.1.19", build="1",
            app_bundle_id="example.app", tunnel_bundle_id="example.app.tunnel",
            app_group_id="group.example.app", team_id="FIXTURE", signer_sha="0" * 64,
            fips_source_relocation=None, fips_source_relocation_sha256=None,
        )
        self.write_json(self.metadata, {
            "checkoutPathSha256": frozen.path_sha256(self.fips),
            "checkoutHead": head, "checkoutTree": tree, "fipsCoreVersion": "1.2.3",
        })
        self.receipt = {
            "receiptSchema": frozen.RECEIPT_SCHEMA,
            "artifactType": "iOS frozen App Store xcarchive",
            "appGitSha": app_head, "appGitTree": app_tree,
            "archiveAppBundleTreeSha256": frozen.tree_sha256(self.app),
            "archivePathSha256": frozen.path_sha256(self.archive),
            "archiveTreeSha256": frozen.tree_sha256(self.archive),
            "fipsCargoMetadataReceiptPathSha256": frozen.path_sha256(self.metadata),
            "fipsCargoMetadataReceiptSha256": frozen.sha256_file(self.metadata),
            "fipsCheckoutPathSha256": frozen.path_sha256(self.fips),
            "fipsCoreVersion": "1.2.3", "fipsGitSha": head, "fipsGitTree": tree,
            "rustBuildProfile": "release", "identity": self.identity, "signing": self.signing,
        }
        self.write_json(self.receipt_path, self.receipt)
        # Source, metadata and archive content checks remain real. Signing is
        # stubbed so the test never needs Apple tools, profiles or devices.
        for name, value in (("bundle_identity", self.identity),
                            ("validate_identity", None),
                            ("signed_bundle_audit", self.signing)):
            mock = patch.object(frozen, name, return_value=value)
            setattr(self, name, mock.start())
            self.addCleanup(mock.stop)

    def git(self, root, *args):
        return subprocess.check_output([
            "git", "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
            "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null",
            "-C", str(root), *args,
        ], text=True, stderr=subprocess.PIPE).strip()

    def repository(self, name):
        path = self.root / name
        path.mkdir()
        self.git(path, "init", "-q")
        (path / "source").write_text(name + "\n")
        self.git(path, "add", "source")
        self.git(path, "commit", "-qm", "fixture")
        return path

    def write_json(self, path, value):
        path.write_text(json.dumps(value, sort_keys=True) + "\n")

    def relocate(self):
        old = self.fips
        self.fips = self.root / "fips-relocated"
        old.rename(self.fips)
        self.assertFalse(old.exists())
        self.args.fips_root = str(self.fips)
        self.proof_path = self.root / "relocation.json"
        self.proof = {
            "receiptSchema": 1, "artifactType": "FIPS validation source relocation",
            "archiveReceiptSha256": frozen.sha256_file(self.receipt_path),
            "fipsCargoMetadataReceiptSha256": frozen.sha256_file(self.metadata),
            "historicalCheckoutPathSha256": self.receipt["fipsCheckoutPathSha256"],
            "validationCheckoutPathSha256": frozen.path_sha256(self.fips),
            "fipsGitSha": self.args.fips_head, "fipsGitTree": self.args.fips_tree,
            "fipsCoreVersion": self.args.fips_version,
        }
        self.pin_proof(self.proof)

    def pin_proof(self, proof):
        self.write_json(self.proof_path, proof)
        self.args.fips_source_relocation = str(self.proof_path)
        self.args.fips_source_relocation_sha256 = frozen.sha256_file(self.proof_path)

    def validate(self):
        with contextlib.redirect_stdout(io.StringIO()) as output:
            result = frozen.validate_archive_receipt(self.args)
        return result, output.getvalue()

    def test_unchanged_path_remains_strict_and_silent(self):
        before = [p.read_bytes() for p in (self.metadata, self.receipt_path)]
        result, output = self.validate()
        self.assertEqual(result[0], self.receipt)
        self.assertEqual(output, "")
        self.assertEqual(before, [p.read_bytes() for p in (self.metadata, self.receipt_path)])
        self.validate_identity.assert_called_once()
        self.signed_bundle_audit.assert_called_once()

    def test_relocated_exact_source_keeps_historical_receipts(self):
        before = [p.read_bytes() for p in (self.metadata, self.receipt_path)]
        self.relocate()
        result, output = self.validate()
        self.assertEqual(result[0], self.receipt)
        audit = json.loads(output)
        self.assertTrue(audit["frozenArchiveSourceValidated"])
        self.assertEqual(audit["fipsSourceRelocation"]["validationCheckoutPathSha256"], frozen.path_sha256(self.fips))
        self.assertEqual(before, [p.read_bytes() for p in (self.metadata, self.receipt_path)])

    def test_missing_incomplete_or_changed_evidence_rejected(self):
        self.relocate()
        original = copy.copy(self.args)
        for path, digest in ((None, None), (str(self.proof_path), None),
                             (None, original.fips_source_relocation_sha256),
                             (str(self.proof_path), "0" * 64)):
            with self.subTest(path=path, digest=digest):
                self.args.fips_source_relocation = path
                self.args.fips_source_relocation_sha256 = digest
                with self.assertRaises(ValueError):
                    self.validate()
        self.args = original
        for key in self.proof:
            with self.subTest(field=key):
                self.pin_proof({**self.proof, key: "wrong"})
                with self.assertRaises(ValueError):
                    self.validate()
        self.pin_proof({**self.proof, "receiptSchema": True})
        with self.assertRaises(ValueError):
            self.validate()

    def test_wrong_or_dirty_current_source_rejected(self):
        self.relocate()
        for key, value in (("fips_root", str(self.source)), ("fips_head", "0" * 40),
                           ("fips_tree", "0" * 40), ("fips_version", "9.9.9")):
            old = getattr(self.args, key)
            with self.subTest(field=key):
                setattr(self.args, key, value)
                with self.assertRaises(ValueError):
                    self.validate()
                setattr(self.args, key, old)
        (self.fips / "source").write_text("changed source\n")
        with self.assertRaisesRegex(ValueError, "dirty"):
            self.validate()
        self.git(self.fips, "add", "source")
        self.git(self.fips, "commit", "-qm", "different revision")
        with self.assertRaisesRegex(ValueError, "HEAD changed"):
            self.validate()

    def test_changed_historical_inputs_rejected(self):
        self.relocate()
        for path in (self.metadata, self.receipt_path):
            with self.subTest(path=path.name):
                original = path.read_bytes()
                path.write_bytes(original + b"\n")
                with self.assertRaises(ValueError):
                    self.validate()
                path.write_bytes(original)

    def test_post_validation_changes_rejected(self):
        self.relocate()
        for path in (self.metadata, self.receipt_path, self.proof_path, self.fips / "source"):
            with self.subTest(path=path.name):
                original = path.read_bytes()
                def changed_during_signing(*args, **kwargs):
                    path.write_bytes(original + b"\n")
                    return self.signing
                self.signed_bundle_audit.side_effect = changed_during_signing
                with self.assertRaises(ValueError):
                    self.validate()
                path.write_bytes(original)

    def test_content_identity_and_signature_checks_remain(self):
        self.relocate()
        self.bundle_identity.return_value = {"fixtureIdentity": "changed"}
        with self.assertRaisesRegex(ValueError, "code identity"):
            self.validate()
        self.bundle_identity.return_value = self.identity
        self.signed_bundle_audit.return_value = {"fixtureSignature": "changed"}
        with self.assertRaisesRegex(ValueError, "signing changed"):
            self.validate()
        self.signed_bundle_audit.return_value = self.signing
        (self.app / "payload").write_bytes(b"changed content")
        with self.assertRaisesRegex(ValueError, "archiveAppBundleTreeSha256"):
            self.validate()

    def test_relocation_cannot_authorize_freeze(self):
        self.relocate()
        with self.assertRaisesRegex(ValueError, "new archive"):
            frozen.validate_source_and_fips(self.args)

    def export_args(self):
        app = self.root / "export.app"
        shutil.copytree(self.app, app)
        ipa = self.root / "fixture.ipa"
        ipa.write_bytes(b"unchanged fixture export")
        self.args.app, self.args.ipa = str(app), str(ipa)
        self.args.output = str(self.root / "export-receipt.json")
        self.args.distribution, self.args.device_udid = "app-store-connect", ""
        mock = patch.object(frozen, "export_equivalence_identity", side_effect=lambda path: (path / "payload").read_bytes())
        mock.start()
        self.addCleanup(mock.stop)

    def test_export_receipt_bytes_unchanged_after_source_relocation(self):
        self.export_args()
        frozen.validate_export(self.args)
        output = pathlib.Path(self.args.output)
        before = output.read_bytes()
        self.relocate()
        with contextlib.redirect_stdout(io.StringIO()):
            frozen.validate_export(self.args)
        self.assertEqual(output.read_bytes(), before)
        output.unlink()
        (pathlib.Path(self.args.app) / "payload").write_bytes(b"wrong export content")
        with contextlib.redirect_stdout(io.StringIO()), self.assertRaisesRegex(ValueError, "content-identical"):
            frozen.validate_export(self.args)
        self.assertFalse(output.exists())

    def test_changes_during_export_validation_rejected_before_receipt(self):
        self.export_args()
        self.relocate()
        calls = 0
        def changed_during_export(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 2:
                self.metadata.write_bytes(self.metadata.read_bytes() + b"\n")
            return self.signing
        self.signed_bundle_audit.side_effect = changed_during_export
        with contextlib.redirect_stdout(io.StringIO()), self.assertRaises(ValueError):
            frozen.validate_export(self.args)
        self.assertFalse(pathlib.Path(self.args.output).exists())

    def test_shell_only_passes_explicit_evidence_to_validation(self):
        script = pathlib.Path(__file__).with_name("ios-build").read_text()
        function = re.search(r"^prepare_frozen_validation_args\(\) \{.*?^\}", script, re.M | re.S).group()
        validate = re.search(r"^validate_frozen_archive\(\) \{.*?^\}", script, re.M | re.S).group()
        freeze = re.search(r"^write_frozen_archive_receipt\(\) \{.*?^\}", script, re.M | re.S).group()
        self.relocate()
        env = {**os.environ, "NVPN_IOS_FIPS_SOURCE_RELOCATION": str(self.proof_path),
               "NVPN_IOS_FIPS_SOURCE_RELOCATION_SHA256": self.args.fips_source_relocation_sha256}
        stub = 'prepare_frozen_revision_args() { FROZEN_REVISION_ARGS=(--fips-root fixture); }\n'
        command = 'set -euo pipefail\n' + stub + function + '\nprepare_frozen_validation_args\nprintf "%s\\0" "${FROZEN_VALIDATION_ARGS[@]}"\n'
        result = subprocess.run(["bash", "-c", command], env=env, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.decode().split("\0")[:-1], [
            "--fips-root", "fixture", "--fips-source-relocation", str(self.proof_path),
            "--fips-source-relocation-sha256", self.args.fips_source_relocation_sha256,
        ])
        env["NVPN_IOS_FIPS_SOURCE_RELOCATION_SHA256"] = ""
        self.assertNotEqual(subprocess.run(["bash", "-c", command], env=env, capture_output=True).returncode, 0)
        # A shell conditional disables errexit inside its called functions.
        # Invalid evidence must still stop before the validator is invoked.
        command = ('set -euo pipefail\n' + stub + function + '\n' + validate
                   + '\npython3() { echo unexpected-validator; return 0; }\n'
                   + 'FROZEN_TOOL=fixture ARCHIVE_PATH=fixture FROZEN_ARCHIVE_RECEIPT=fixture\n'
                   + 'if validate_frozen_archive; then exit 99; else exit 0; fi\n')
        result = subprocess.run(["bash", "-c", command], env=env, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn(b"unexpected-validator", result.stdout)
        result = subprocess.run(["bash", "-c", 'set -euo pipefail\n' + stub + freeze + '\nwrite_frozen_archive_receipt'], env=env, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"cannot authorize a new archive", result.stderr)

    def test_relocation_never_replaces_or_builds_a_missing_or_invalid_archive(self):
        script = pathlib.Path(__file__).with_name("ios-build").read_text()
        archive = re.search(r"^run_ios_archive\(\) \{.*?^\}", script, re.M | re.S).group()
        self.relocate()
        env = {**os.environ, "NVPN_IOS_FIPS_SOURCE_RELOCATION": str(self.proof_path),
               "NVPN_IOS_FIPS_SOURCE_RELOCATION_SHA256": self.args.fips_source_relocation_sha256,
               "ARCHIVE_PATH": str(self.archive), "FROZEN_DIR": str(self.root / "frozen"),
               "FROZEN_ARCHIVE_RECEIPT": str(self.receipt_path)}
        stub = '''prepare_frozen_revision_args() { :; }
validate_frozen_archive() { return "$FIXTURE_VALIDATION_STATUS"; }
quarantine_stale_frozen_state() { echo unexpected-quarantine; exit 99; }
ensure_profiles() { echo unexpected-build; exit 99; }
'''
        command = 'set -euo pipefail\n' + stub + archive + '\nrun_ios_archive\n'
        result = subprocess.run(["bash", "-c", command], env={**env, "FIXTURE_VALIDATION_STATUS": "0"}, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(b"Reusing the exact verified", result.stdout)
        for archive_path in (self.archive, self.root / "missing-archive"):
            with self.subTest(archive=archive_path.name):
                result = subprocess.run(["bash", "-c", command], env={
                    **env, "ARCHIVE_PATH": str(archive_path), "FIXTURE_VALIDATION_STATUS": "1",
                }, capture_output=True)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertNotIn(b"unexpected-", result.stdout)
                self.assertIn(b"refusing to replace", result.stderr)
        self.assertTrue(self.archive.is_dir())
        self.assertTrue(self.receipt_path.is_file())


if __name__ == "__main__":
    unittest.main()
