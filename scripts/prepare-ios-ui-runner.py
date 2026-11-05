#!/usr/bin/env python3
"""Prepare UI tests independently of the signed application and Rust build."""

import hashlib
import json
from pathlib import Path
import plistlib
import subprocess
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "work/ios-ui-runner"
SPEC = """name: NostrVpnUIRunner
options:
  deploymentTarget:
    iOS: '17.0'
settings:
  base:
    SWIFT_VERSION: '5.0'
targets:
  NostrVpnIosUITests:
    type: bundle.ui-testing
    platform: iOS
    sources:
      - path: ../../ios/UITests
    settings:
      base:
        PRODUCT_BUNDLE_IDENTIFIER: fi.siriusbusiness.nvpn.UITests
        PRODUCT_NAME: '$(TARGET_NAME)'
        PRODUCT_MODULE_NAME: '$(TARGET_NAME)'
        GENERATE_INFOPLIST_FILE: YES
schemes:
  NostrVpnIosUITests:
    build:
      targets:
        NostrVpnIosUITests: all
    test:
      config: Release
      targets:
        - NostrVpnIosUITests
"""

FILE_SHARING_INFO = {
    "CFBundleDisplayName": "Nostr VPN Test Files",
    "LSSupportsOpeningDocumentsInPlace": True,
    "UIFileSharingEnabled": True,
}


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def main():
    if not sys.argv[1:]:
        OUT.mkdir(parents=True, exist_ok=False)
        (OUT / "project.yml").write_text(SPEC)
        return
    if sys.argv[1:] not in (["--file-sharing"], ["--receipt"]):
        raise SystemExit("usage: prepare-ios-ui-runner.py [--file-sharing|--receipt]")
    products = OUT / "DerivedData/Build/Products"
    runner = products / "Release-iphoneos/NostrVpnIosUITests-Runner.app"
    if not runner.is_dir() or list(products.rglob("Nostr VPN.app")):
        raise SystemExit("Expected only the test runner, without an application build")
    if len(list(products.glob("*.xctestrun"))) != 1:
        raise SystemExit("Expected exactly one test plan")
    info_path = runner / "Info.plist"
    info = plistlib.loads(info_path.read_bytes())
    if info.get("CFBundleIdentifier") != "fi.siriusbusiness.nvpn.UITests.xctrunner":
        raise SystemExit("Refusing to modify an unexpected application")
    if sys.argv[1:] == ["--file-sharing"]:
        # Xcode's INFOPLIST_KEY settings affect the .xctest plug-in, not its
        # generated host. Apply this to the host before its final developer sign.
        info.update(FILE_SHARING_INFO)
        info_path.write_bytes(plistlib.dumps(info, fmt=plistlib.FMT_BINARY))
        return
    if any(type(info.get(key)) is not type(value) or info[key] != value
           for key, value in FILE_SHARING_INFO.items()):
        raise SystemExit("Prepare the runner host's Files access before packaging")
    archive = OUT / "ios-ui-runner.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        tar.add(products, arcname="Products")
    def git(*args):
        return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()
    proof = {
        "commit": git("rev-parse", "HEAD"),
        "uiSourceTree": git("rev-parse", "HEAD:ios/UITests"),
        "platform": "ios", "architecture": "arm64", "configuration": "Release",
        "signed": False, "testsExecuted": False, "releasePackage": False,
        "runnerFileSharingPrepared": True,
        "appBuilt": False, "rustBuilt": False,
        "archive": archive.name, "archiveBytes": archive.stat().st_size,
        "archiveSHA256": digest(archive), "projectSHA256": digest(OUT / "project.yml"),
        "xcode": subprocess.check_output(["xcodebuild", "-version"], text=True).strip(),
    }
    (OUT / "build-receipt.json").write_text(json.dumps(proof, indent=2) + "\n")


if __name__ == "__main__":
    main()
