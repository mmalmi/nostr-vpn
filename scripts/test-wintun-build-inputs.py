#!/usr/bin/env python3
"""Exercise the actual compiled Wintun build script with isolated cache fixtures."""

import argparse
import hashlib
import os
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile
import tomllib
import unittest


class BuildInputs(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="nvpn-wintun-inputs-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.home = self.root / "cargo"
        self.registry = self.home / "registry" / "src"
        self.registry.mkdir(parents=True)
        self.out = self.root / "target" / "debug" / "build" / "fixture" / "out"
        self.out.mkdir(parents=True)
        self.output = self.root / "target" / "debug" / "wintun.dll"

    def seed(self, registry="registry-a", package=None, arch="amd64", data=None):
        path = self.registry / registry / (package or self.package) / "wintun" / "bin" / arch / "wintun.dll"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(self.dlls[arch] if data is None else data)
        return path

    def run_build(self, arch="x86_64", target_os="windows", error=None):
        before = self.output.read_bytes() if self.output.exists() else None
        result = subprocess.run(
            [str(self.build_script)],
            env={**os.environ, "CARGO_HOME": str(self.home), "OUT_DIR": str(self.out),
                 "PROFILE": "debug", "CARGO_CFG_TARGET_OS": target_os,
                 "CARGO_CFG_TARGET_ARCH": arch},
            capture_output=True, text=True, timeout=10,
        )
        if error:
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn(error, result.stderr)
            self.assertNotIn("cargo:rustc-env=NOSTR_VPN_WINTUN_DLL_SOURCE=", result.stdout)
            self.assertEqual(self.output.read_bytes() if self.output.exists() else None, before)
        else:
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            if target_os == "windows":
                self.assertIn(f"cargo:rustc-env=NOSTR_VPN_WINTUN_DLL_SOURCE={self.output}", result.stdout)
        return result

    def test_all_architecture_hashes_match_locked_archive(self):
        for arch, directory in {"x86": "x86", "x86_64": "amd64", "arm": "arm", "aarch64": "arm64"}.items():
            with self.subTest(arch=arch):
                self.seed(arch=directory)
                self.run_build(arch=arch)
                self.assertEqual(self.output.read_bytes(), self.dlls[directory])

    def test_wrong_version_is_not_used(self):
        self.seed(package="wintun-0.5.0")
        self.run_build(error="not found")

    def test_unrelated_bindings_package_is_not_used(self):
        self.seed(package="wintun-bindings-0.7.40")
        self.run_build(error="not found")

    def test_exact_package_wins_over_other_cached_packages(self):
        self.seed(package="wintun-0.5.0", data=b"old")
        self.seed(package="wintun-bindings-0.7.40", data=b"unrelated")
        self.seed()
        self.run_build()
        self.assertEqual(self.output.read_bytes(), self.dlls["amd64"])

    def test_changed_dll_fails_without_replacing_existing_output(self):
        self.seed(data=b"changed")
        self.output.write_bytes(b"existing output")
        self.run_build(error="SHA-256 mismatch")

    def test_wrong_architecture_bytes_fail(self):
        self.seed(data=self.dlls["arm64"])
        self.run_build(error="SHA-256 mismatch")

    def test_conflicting_registry_copies_fail_in_either_order(self):
        for valid_registry, invalid_registry in [("registry-a", "registry-b"), ("registry-b", "registry-a")]:
            with self.subTest(valid_registry=valid_registry):
                self.seed(registry=valid_registry)
                self.seed(registry=invalid_registry, data=b"stale copy")
                self.run_build(error="SHA-256 mismatch")

    def test_identical_verified_registry_copies_are_accepted(self):
        self.seed(registry="registry-a")
        self.seed(registry="registry-b")
        self.run_build()
        self.assertEqual(self.output.read_bytes(), self.dlls["amd64"])

    def test_missing_dll_fails(self):
        self.seed().unlink()
        self.run_build(error="failed to read pinned")

    def test_missing_registry_fails(self):
        self.registry.rmdir()
        self.run_build(error="failed to read")

    def test_unsupported_architecture_fails(self):
        self.seed()
        self.run_build(arch="riscv64", error="unsupported windows arch")

    def test_stale_output_is_replaced_and_current_output_is_preserved(self):
        self.seed()
        self.output.write_bytes(b"stale output")
        self.run_build()
        self.assertEqual(self.output.read_bytes(), self.dlls["amd64"])
        previous_mtime = self.output.stat().st_mtime_ns
        self.run_build()
        self.assertEqual(self.output.stat().st_mtime_ns, previous_mtime)

    def test_non_windows_build_does_not_require_wintun(self):
        self.registry.rmdir()
        self.run_build(target_os="linux")
        self.assertFalse(self.output.exists())


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-script", type=Path, required=True,
                        help="build-script-build.exe from this candidate's Windows cargo check")
    parser.add_argument("--crate-archive", type=Path, required=True,
                        help="cached wintun crate archive matching Cargo.lock")
    args = parser.parse_args()
    repo = Path(__file__).resolve().parent.parent
    lock = tomllib.loads((repo / "Cargo.lock").read_text())
    packages = [p for p in lock["package"] if p["name"] == "wintun"]
    if len(packages) != 1:
        parser.error("expected one locked wintun package")
    locked = packages[0]
    archive_hash = hashlib.sha256(args.crate_archive.read_bytes()).hexdigest()
    if archive_hash != locked["checksum"]:
        parser.error("crate archive SHA-256 does not match Cargo.lock")
    crate = repo / "crates" / "nostr-vpn-wintun"
    manifest = tomllib.loads((crate / "Cargo.toml").read_text())
    if manifest["target"]['cfg(target_os = "windows")']["dependencies"]["wintun"] != "=" + locked["version"]:
        parser.error("Wintun dependency must exactly match the locked version")
    BuildInputs.package = "wintun-" + locked["version"]
    source = (crate / "build.rs").read_text()
    if re.search(r'const WINTUN_PACKAGE: &str = "([^"]+)";', source).group(1) != BuildInputs.package or archive_hash not in source:
        parser.error("build script provenance does not match Cargo.lock")
    BuildInputs.build_script = args.build_script.resolve(strict=True)
    with tarfile.open(args.crate_archive) as archive:
        BuildInputs.dlls = {arch: archive.extractfile(f"{BuildInputs.package}/wintun/bin/{arch}/wintun.dll").read()
                           for arch in ("x86", "amd64", "arm", "arm64")}
    print(f"Verified locked crate SHA-256 {archive_hash}", flush=True)
    unittest.main(argv=[__file__], verbosity=2)
