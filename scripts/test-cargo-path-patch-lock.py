#!/usr/bin/env python3
"""Source-only fixtures for legacy and DTLS-fork FIPS provenance."""

import pathlib
import runpy
import subprocess
import tempfile
import unittest


SCRIPTS = pathlib.Path(__file__).resolve().parent
VERIFIER = runpy.run_path(str(SCRIPTS / "verify-cargo-path-patch-lock.py"))


def specifications(current=True):
    result = {name: "0.17.2" for name in VERIFIER["PATCH_CRATES"]}
    result.update({
        "nvpn-fips-core": "0.4.110" if current else "0.4.107",
        "nvpn-fips-endpoint": "0.4.110" if current else "0.4.107",
        "nvpn-fips-identity": "0.3.3",
        "nvpn-webrtc": "0.17.4" if current else "0.17.3",
    })
    if current:
        result["nvpn-dtls"] = "0.17.3"
    return result


def arguments(specs):
    return [f"{name}={version}" for name, version in specs.items()]


def lock(specs):
    return ("version = 4\n\n" + "".join(
        f'[[package]]\nname = "{name}"\nversion = "{version}"\n'
        'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
        f'checksum = "{"a" * 64}"\n\n'
        for name, version in specs.items()
    )).encode()


class PatchProvenanceTests(unittest.TestCase):
    def test_legacy_and_current_lock_sets(self):
        for current in (False, True):
            with self.subTest(current=current):
                specs = specifications(current)
                self.assertEqual(VERIFIER["package_specs"](arguments(specs)), specs)
                self.assertEqual(VERIFIER["lock_specs"](lock(specs)), specs)
                realized = VERIFIER["expected_realized_lock"](lock(specs), specs)
                self.assertNotIn(b"source =", realized)
                self.assertNotIn(b"checksum =", realized)
                self.assertEqual(realized.count(b"[[package]]"), 9 if current else 8)

    def test_missing_unknown_duplicate_and_mismatched_packages(self):
        specs = specifications()
        for bad in (
            arguments(specs)[:-1],
            arguments(specs)[:-1] + ["unknown=0.17.3"],
            arguments(specs) + ["nvpn-dtls=0.17.3"],
            arguments(specifications(False)) + ["nvpn-dtls=0.17.3"],
        ):
            with self.subTest(bad=bad), self.assertRaises(SystemExit):
                VERIFIER["package_specs"](bad)
        for changed in (
            {key: value for key, value in specs.items() if key != "nvpn-dtls"},
            {**specs, "nvpn-dtls": "0.17.2"},
        ):
            with self.subTest(changed=changed), self.assertRaises(SystemExit):
                VERIFIER["expected_realized_lock"](lock(changed), specs)
        with self.assertRaises(SystemExit):
            VERIFIER["lock_specs"](lock(dict(list(specs.items())[:-1])))

    def test_manifest_requires_exact_dtls_identity_and_dependency(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            for current in (False, True):
                specs = specifications(current)
                for name, path in VERIFIER["patch_crates"](specs["nvpn-webrtc"]).items():
                    manifest = root / path / "Cargo.toml"
                    manifest.parent.mkdir(parents=True, exist_ok=True)
                    manifest.write_text(f'[package]\nname = "{name}"\nversion = "{specs[name]}"\n')
                webrtc = root / "vendor/webrtc/Cargo.toml"
                dependency = ('\n[dependencies.dtls]\npackage = "nvpn-dtls"\n'
                              'path = "../dtls"\nversion = "=0.17.3"\n')
                if current:
                    webrtc.write_text(webrtc.read_text() + dependency)
                self.assertEqual(VERIFIER["manifest_specs"](str(root)), specs)
            original = webrtc.read_text()
            for old, new in (
                ('package = "nvpn-dtls"', 'package = "dtls"'),
                ('path = "../dtls"', 'path = "../other"'),
                ('version = "=0.17.3"', 'version = "=0.17.2"'),
            ):
                webrtc.write_text(original.replace(old, new))
                with self.subTest(new=new), self.assertRaises(SystemExit):
                    VERIFIER["manifest_specs"](str(root))
            webrtc.write_text(original)
            dtls = root / "vendor/dtls/Cargo.toml"
            dtls.write_text(dtls.read_text().replace('name = "nvpn-dtls"', 'name = "unknown"'))
            with self.assertRaises(SystemExit):
                VERIFIER["manifest_specs"](str(root))
            dtls.unlink()
            with self.assertRaises(SystemExit):
                VERIFIER["manifest_specs"](str(root))

    def test_guest_arguments_preserve_artifact_fields_for_both_sets(self):
        source = (SCRIPTS / "lib-ubuntu-vm-imported-release.sh").read_text()
        guest = source.split("<<'GUEST'\nset -euo pipefail\ntrap 'printf \"Ubuntu VM import", 1)[1]
        guest = "set -euo pipefail\ntrap 'printf \"Ubuntu VM import" + guest.split("write_import_phase() {", 1)[0]
        assertions = '''
[[ "$app_hash" == artifact-1 && "$app_size" == artifact-2 ]]
[[ "$harness_sha" == artifact-16 && "$harness_tree" == artifact-17 ]]
python3 "$VERIFIER_PATH" --validate-specs "${fips_patch_packages[@]}"
'''
        for current in (False, True):
            with self.subTest(current=current):
                result = subprocess.run(
                    ["bash", "-c", 'VERIFIER_PATH="$1"; shift\n' + guest + assertions,
                     "fixture", str(SCRIPTS / "verify-cargo-path-patch-lock.py"),
                     *[f"source-{index}" for index in range(1, 14)],
                     *arguments(specifications(current)),
                     *[f"artifact-{index}" for index in range(1, 18)]],
                    capture_output=True, text=True,
                )
                self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
