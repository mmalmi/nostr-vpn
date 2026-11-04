#!/usr/bin/env python3
"""Small adversarial AAB/APK fixtures; no Android tools or signatures created."""

import base64
import hashlib
from pathlib import Path
import stat
import sys
import tempfile
import unittest
import warnings
import zipfile
from types import SimpleNamespace
from unittest.mock import patch

sys.dont_write_bytecode = True
import android_hosted_content as content


class AndroidContent(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="nvpn-android-content-fixture-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.payload = {"base/lib/arm64-v8a/libnostr_vpn_app_core.so": b"exact JNI",
            "base/dex/classes.dex": b"exact DEX", "base/assets/help.txt": b"exact asset",
            "META-INF/services/example.Service": b"important metadata",
            "BundleConfig.pb": b"bundle config"}

    def archive(self, name, files):
        path = self.root / name
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for key, value in files.items():
                archive.writestr(key, value)
        return path

    def signed_files(self, *, original_manifest=False):
        main = "Manifest-Version: 1.0\r\nCreated-By: 17 (fixture)\r\n"
        if original_manifest:
            main += "Custom-Product: preserved\r\n"
        manifest = main + "\r\n"
        for name, value in self.payload.items():
            digest = base64.b64encode(hashlib.sha256(value).digest()).decode()
            manifest += f"Name: {name}\r\nSHA-256-Digest: {digest}\r\n\r\n"
        return {**self.payload, content.MANIFEST: manifest.encode(),
                "META-INF/RELEASE.SF": b"fixture signature descriptor",
                "META-INF/RELEASE.RSA": b"fixture signature block"}

    def test_unsigned_payload_and_original_manifest_semantics_are_preserved(self):
        for present in (False, True):
            original = dict(self.payload)
            if present:
                original[content.MANIFEST] = b"Manifest-Version: 1.0\r\nCustom-Product: preserved\r\n\r\n"
            unsigned = self.archive("unsigned.aab", original)
            signed = self.archive("signed.aab", self.signed_files(original_manifest=present))
            result = content.aab_content_identity(unsigned, signed)
            self.assertEqual(set(result["payload"]), set(self.payload))

    def test_meta_inf_content_signature_pairs_and_manifest_digests_are_not_ignored(self):
        unsigned = self.archive("unsigned.aab", self.payload)
        changes = [
            {"META-INF/services/example.Service": b"tampered"},
            {"META-INF/OTHER.RSA": b"second signer"},
            {"META-INF/arbitrary.txt": b"new metadata"},
            {"base/dex/classes.dex": b"different compiled code"},
            {content.MANIFEST: self.signed_files()[content.MANIFEST].replace(b"Created-By:", b"Class-Path:")},
            {content.MANIFEST: self.signed_files()[content.MANIFEST].replace(b"SHA-256-Digest:", b"SHA-1-Digest:")},
        ]
        for change in changes:
            signed = self.archive("changed.aab", {**self.signed_files(), **change})
            with self.subTest(change=list(change)), self.assertRaises(ValueError):
                content.aab_content_identity(unsigned, signed)
        missing = self.signed_files()
        del missing["META-INF/services/example.Service"]
        with self.assertRaises(ValueError):
            content.aab_content_identity(unsigned, self.archive("missing.aab", missing))

    def test_duplicate_and_linked_zip_entries_are_rejected(self):
        path = self.archive("unsafe.aab", self.payload)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with zipfile.ZipFile(path, "a") as archive:
                archive.writestr("BundleConfig.pb", b"replacement")
        with self.assertRaisesRegex(ValueError, "duplicate"):
            content.zip_identity(path)
        path = self.archive("linked.aab", self.payload)
        with zipfile.ZipFile(path, "a") as archive:
            entry = zipfile.ZipInfo("escape")
            entry.create_system = 3
            entry.external_attr = (stat.S_IFLNK | 0o777) << 16
            archive.writestr(entry, "../outside")
        with self.assertRaisesRegex(ValueError, "linked"):
            content.zip_identity(path)

    def test_apk_must_preserve_exact_native_dex_and_assets_without_extras(self):
        aab = self.archive("input.aab", self.payload)
        files = {"lib/arm64-v8a/libnostr_vpn_app_core.so": b"exact JNI",
                 "classes.dex": b"exact DEX", "assets/help.txt": b"exact asset"}
        content.apk_runtime_identity(aab, self.archive("valid.apk", files))
        for changes in ({"classes.dex": b"wrong app"}, {"classes2.dex": b"extra code"},
                        {"lib/arm64-v8a/extra.so": b"extra native"}, {"assets/extra": b"extra asset"}):
            with self.subTest(changes=list(changes)), self.assertRaises(ValueError):
                content.apk_runtime_identity(aab, self.archive("wrong.apk", {**files, **changes}))

    def test_manifest_continuations_preserve_utf8_and_reject_duplicate_names(self):
        main, entries = content.manifest_sections(b"Manifest-Version: 1.0\r\n\r\nName: assets/\xc3\r\n \xa9\r\nX: y\r\n\r\n")
        self.assertEqual(entries, {"assets/é": {"x": "y"}})
        with self.assertRaisesRegex(ValueError, "duplicate"):
            content.manifest_sections(b"Manifest-Version: 1.0\n\nName: a\nX: y\n\nName: a\nX: z\n\n")

    def test_signer_pin_and_complete_manifest_signature_are_mandatory(self):
        files = self.signed_files()
        files["META-INF/RELEASE.SF"] = ("Signature-Version: 1.0\r\nSHA-256-Digest-Manifest: "
            + base64.b64encode(hashlib.sha256(files[content.MANIFEST]).digest()).decode() + "\r\n\r\n").encode()
        signed = self.archive("signed.aab", files)
        signer_der = b"fixture DER verified only by mocked CMS boundary"
        expected = hashlib.sha256(signer_der).hexdigest()
        def cms(command, **kwargs):
            self.assertEqual(command[:4], ["openssl", "cms", "-verify", "-binary"])
            self.assertNotIn("-nosigs", command)
            self.assertNotIn("-no_content_verify", command)
            Path(command[command.index("-signer") + 1]).write_bytes(b"-----BEGIN CERTIFICATE-----\n"
                + base64.b64encode(signer_der) + b"\n-----END CERTIFICATE-----\n")
            return SimpleNamespace(stdout=files["META-INF/RELEASE.SF"])
        pair = ["META-INF/RELEASE.SF", "META-INF/RELEASE.RSA"]
        with patch.object(content.subprocess, "run", side_effect=cms):
            self.assertEqual(content.verify_aab_signer(signed, pair, expected), expected)
            with self.assertRaisesRegex(ValueError, "different certificate"):
                content.verify_aab_signer(signed, pair, "0" * 64)
        files["META-INF/RELEASE.SF"] = b"Signature-Version: 1.0\r\nSHA-256-Digest-Manifest: wrong\r\n\r\n"
        with self.assertRaisesRegex(ValueError, "complete manifest"):
            content.verify_aab_signer(self.archive("wrong-signature.aab", files), pair, expected)


if __name__ == "__main__":
    unittest.main()
