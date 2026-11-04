#!/usr/bin/env python3
"""Build unsigned products with the frozen source's existing Apple recipes.

This produces neither an accepted app nor a publication receipt. Signing,
export, notarization and all runtime gates stay local.
"""

import hashlib
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import platform
import plistlib
import shutil
import signal
import subprocess
import sys
import tarfile
import time


def capture(*args, cwd=None):
    return subprocess.check_output(args, cwd=cwd, text=True).strip()


def digest(path):
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def exact_source(root, prefix):
    identity = {"commit": capture("git", "rev-parse", "HEAD", cwd=root),
                "tree": capture("git", "rev-parse", "HEAD^{tree}", cwd=root)}
    assert identity == {"commit": os.environ[prefix + "_COMMIT"],
                        "tree": os.environ[prefix + "_TREE"]}, "source identity differs"
    assert not capture("git", "status", "--porcelain", "--untracked-files=all", cwd=root)
    return identity


def main():
    selected, app_arg, fips_arg, output_arg = sys.argv[1:]
    assert selected in {"ios", "ios-join", "macos", "macos-support"}
    assert platform.system() == "Darwin" and platform.machine() == "arm64"
    app, fips, output = (Path(p).resolve() for p in (app_arg, fips_arg, output_arg))
    assert not output.exists(), "output must be fresh"
    output.mkdir()
    app_identity = exact_source(app, "APP")
    fips_identity = exact_source(fips, "FIPS")
    assert capture("rustc", "--version") == "rustc 1.95.0 (59807616e 2026-04-14)"
    assert capture("xcodebuild", "-version") == "Xcode 26.6\nBuild version 17F113"
    assert capture("xcodegen", "--version") == "Version: 2.45.4"
    assert capture("xcode-select", "-p") == os.environ["DEVELOPER_DIR"]
    sdk_versions = {sdk: capture("xcrun", "--sdk", sdk, "--show-sdk-version")
                    for sdk in ("iphoneos", "iphonesimulator", "macosx")}
    assert sdk_versions == {"iphoneos": "26.5", "iphonesimulator": "26.5", "macosx": "26.5"}
    initial_free = shutil.disk_usage(app).free
    admission = {"freeBytes": initial_free, "entryRequiredBytes": 20 * 1024**3,
                 "liveFloorBytes": 4 * 1024**3,
                 "maximumGrowthBudgetBytes": 16 * 1024**3,
                 "budgetIsMeasuredPeak": False, "admitted": initial_free >= 20 * 1024**3}
    (output / "admission.json").write_text(json.dumps(admission, indent=2) + "\n")
    assert admission["admitted"], "hosted space admission failed; see admission.json"
    committed_lock = (app / "Cargo.lock").read_bytes()
    specs = capture("python3", str(app / "scripts/verify-cargo-path-patch-lock.py"),
                    "--manifest-specs", str(fips)).splitlines()
    realized = output / "realized-Cargo.lock"
    subprocess.run(["python3", str(app / "scripts/verify-cargo-path-patch-lock.py"),
                    "--materialize", str(app / "Cargo.lock"), str(realized), *specs], check=True)
    assert digest(realized) == "41067773c75d291993622ac7d0a66ac77e3ce050ff6b9a646466a413f5cb065a"
    (app / "Cargo.lock").write_bytes(realized.read_bytes())
    env = dict(os.environ, CARGO_TARGET_DIR=str(app / "target"),
               NVPN_MACOS_CARGO_TARGET_DIR=str(app / "target"),
               NVPN_FIPS_REPO_PATH=str(fips), NVPN_EXPECTED_FIPS_GIT_SHA=fips_identity["commit"],
               NVPN_BUILD_GIT_SHA=app_identity["commit"],
               SOURCE_DATE_EPOCH=capture("git", "show", "-s", "--format=%ct", "HEAD", cwd=app),
               ZERO_AR_DATE="1", NVPN_MACOS_CARGO_LOCKED="1",
               NVPN_MACOS_RUST_TARGETS="aarch64-apple-darwin", NVPN_MACOS_RUST_PROFILE="release",
               NVPN_IOS_RUST_PROFILE="release")
    env["NVPN_BUILD_TIMESTAMP_UTC"] = datetime.fromtimestamp(
        int(env["SOURCE_DATE_EPOCH"]), timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    env["SWIFTC_MAXIMUM_DETERMINISM"] = "1"
    if selected in {"ios", "ios-join"}:
        product = (Path("dist/ios/NostrVpnIos.xcarchive") if selected == "ios"
                   else Path("ios/.build/JoinReleaseDerivedData/Build/Products"))
        recipes = [["tools/run-ios", "xcframework"], ["tools/run-ios", "project"],
                   ["xcodebuild", "-jobs", "2", "-project", "ios/NostrVpnIos.xcodeproj",
                    "-scheme", "NostrVpnIos", "-configuration", "Release",
                    "-destination", "generic/platform=iOS",
                    "-derivedDataPath", ("ios/.build/ReleaseDerivedData" if selected == "ios"
                                         else "ios/.build/JoinReleaseDerivedData"),
                    "CODE_SIGNING_ALLOWED=NO", "CODE_SIGNING_REQUIRED=NO",
                    "CODE_SIGN_IDENTITY=", "DEVELOPMENT_TEAM=",
                    "NVPN_BUILD_GIT_SHA=" + env["NVPN_BUILD_GIT_SHA"],
                    "NVPN_BUILD_TIMESTAMP_UTC=" + env["NVPN_BUILD_TIMESTAMP_UTC"]]]
        if selected == "ios":
            recipes[-1] += ["-archivePath", str(product), "archive"]
        else:
            recipes[-1] += ["ARCHS=arm64",
                           "OTHER_SWIFT_FLAGS=$(inherited) -DNVPN_RELEASE_JOIN_TESTING",
                           "build-for-testing"]
    elif selected == "macos-support":
        product = Path("macos/.build/hosted-gate-support")
        env.update(NVPN_MACOS_HOST_TARGET="aarch64-apple-darwin",
                   NVPN_MACOS_GATE_SUPPORT_DIR=str(app / product))
        recipes = [["scripts/macos-build", "macos-gate-support"]]
    else:
        product = Path("macos/.build/ReleaseDerivedData/Build/Products/Release/Nostr VPN.app")
        recipes = [["scripts/macos-build", "macos-xcframework"],
                   ["scripts/macos-build", "macos-xcodeproj"],
                   ["xcodebuild", "-jobs", "1", "-project", "macos/NostrVpnMac.xcodeproj",
                    "-scheme", "NostrVpnMac", "-configuration", "Release",
                    "-derivedDataPath", "macos/.build/ReleaseDerivedData",
                    "-destination", "generic/platform=macOS", "ARCHS=arm64",
                    "ONLY_ACTIVE_ARCH=NO", "SKIP_INSTALL=NO",
                    "SWIFT_COMPILATION_MODE=singlefile", "SWIFT_ENABLE_BATCH_MODE=NO",
                    "CODE_SIGNING_ALLOWED=NO", "CODE_SIGNING_REQUIRED=NO",
                    "CODE_SIGN_IDENTITY=", "DEVELOPMENT_TEAM=",
                    "OTHER_LDFLAGS=$(inherited) -Wl,-S", "build"]]
    started = time.monotonic()
    minimum_free = initial_free
    reason = None
    code = None
    try:
        with (output / "build.log").open("w") as log:
            for recipe in recipes:
                child = subprocess.Popen(recipe, cwd=app, env=env, stdout=log,
                                         stderr=subprocess.STDOUT, start_new_session=True)
                while child.poll() is None:
                    minimum_free = min(minimum_free, shutil.disk_usage(app).free)
                    if minimum_free < 4 * 1024**3 or time.monotonic() - started > 4800:
                        reason = "hosted disk floor or 80-minute build deadline"
                        os.killpg(child.pid, signal.SIGTERM)
                        try:
                            child.wait(timeout=30)
                        except subprocess.TimeoutExpired:
                            os.killpg(child.pid, signal.SIGKILL)
                        break
                    time.sleep(5)
                code = child.wait()
                assert code == 0 and reason is None, "canonical Apple recipe failed; see build.log"
        assert (app / "Cargo.lock").read_bytes() == realized.read_bytes(), "realized dependency graph changed"
    finally:
        (app / "Cargo.lock").write_bytes(committed_lock)
        (output / "resources.json").write_text(json.dumps({
            "initialFreeBytes": initial_free, "minimumFreeBytes": minimum_free,
            "maximumObservedVolumeGrowthBytes": initial_free - minimum_free,
            "elapsedSeconds": round(time.monotonic() - started, 1),
            "exitCode": code, "abortReason": reason}, indent=2) + "\n")
    # Generated macOS bindings are included explicitly, never silently discarded.
    changed = capture("git", "diff", "--name-only", cwd=app).splitlines()
    allowed_project = ("ios/NostrVpnIos.xcodeproj/project.pbxproj" if selected.startswith("ios")
                       else "macos/NostrVpnMac.xcodeproj/project.pbxproj")
    assert all(p == allowed_project or
               (selected == "macos" and p.startswith("macos/Bindings/")) for p in changed)
    exact_source(fips, "FIPS")
    paths = [product]
    if selected == "macos":
        paths += [Path("macos/Bindings"), Path("macos/Resources/binaries/nvpn")]
        cli_version = capture(str(app / "macos/Resources/binaries/nvpn"), "version", "--verbose")
        assert "4.1.21" in cli_version and "0.4.117 (rev d0b18f2d1b)" in cli_version
    elif selected.startswith("ios"):
        # Preserve the original hosted path-bound proof. A local importer must
        # validate it as a NEW unsigned archive, not claim retained-archive reuse.
        paths += [Path("artifacts/mobile-ios/fips-linkage.json")]
        linkage = json.loads((app / paths[-1]).read_text())
        assert linkage["checkoutHead"] == fips_identity["commit"]
        assert linkage["checkoutTree"] == fips_identity["tree"]
        assert linkage["fipsCoreVersion"] == "0.4.117"
    if selected == "ios-join":
        # The existing physical join gate uses this separate test-only app;
        # production's signed archive and Info.plist remain unchanged.
        info = app / product / "Release-iphoneos/Nostr VPN.app/Info.plist"
        with info.open("rb") as stream:
            values = plistlib.load(stream)
        values.update(CFBundleDisplayName="Nostr VPN Test Files",
                      UIFileSharingEnabled=True,
                      LSSupportsOpeningDocumentsInPlace=True)
        info.write_bytes(plistlib.dumps(values))
        plans = list((app / product).glob("*.xctestrun"))
        assert len(plans) == 1, "expected one exact join test plan"
        assert (app / product / "Release-iphoneos/NostrVpnIosUITests-Runner.app").is_dir()
        paths = [product / "Release-iphoneos/Nostr VPN.app",
                 product / "Release-iphoneos/NostrVpnIosUITests-Runner.app",
                 plans[0].relative_to(app), Path("artifacts/mobile-ios/fips-linkage.json")]
    if selected == "macos-support":
        expected = {"fixtures/desktop_manual_join_e2e_fixture",
                    "drivers/desktop-manual-join-ax", "drivers/macos-service-toggle-ax"}
        assert {str(p.relative_to(app / product)) for p in (app / product).rglob("*")
                if p.is_file()} == expected, "support producer changed its output contract"
    files = []
    for relative in paths:
        path = app / relative
        assert path.exists() and not path.is_symlink()
        for entry in sorted(path.rglob("*")) if path.is_dir() else [path]:
            assert not entry.is_symlink(), "unexpected symlink in Apple inputs"
            if entry.is_file():
                files.append({"path": str(entry.relative_to(app)), "bytes": entry.stat().st_size,
                              "sha256": digest(entry)})
    archive = output / (selected + "-unsigned-release.tar.gz")
    # Include the uncompressed size as the conservative archive growth budget.
    payload_bytes = sum(entry["bytes"] for entry in files)
    assert shutil.disk_usage(output).free >= payload_bytes + 4 * 1024**3
    with tarfile.open(archive, "w:gz") as tar:
        for relative in paths:
            tar.add(app / relative, arcname=str(relative))
    receipt = {"schema": 1, "app": app_identity, "fips": fips_identity,
               "producerCommit": os.environ["GITHUB_SHA"], "runId": os.environ["GITHUB_RUN_ID"],
               "runAttempt": os.environ["GITHUB_RUN_ATTEMPT"], "platform": selected,
               "configuration": "Release", "recipes": recipes, "sdks": sdk_versions,
               "xcode": capture("xcodebuild", "-version"), "rustc": capture("rustc", "-Vv"),
               "swift": capture("xcrun", "swift", "--version"),
               "xcodegen": capture("xcodegen", "--version"),
               "runnerImageVersion": os.environ.get("ImageVersion"),
               "runnerImageOS": os.environ.get("ImageOS"),
               "macOS": capture("sw_vers"),
               "generatedProjectSha256": digest(app / allowed_project),
               "sourceDateEpoch": env["SOURCE_DATE_EPOCH"],
               "committedLockSha256": hashlib.sha256(committed_lock).hexdigest(),
               "realizedLockSha256": digest(realized), "files": files,
               "archive": archive.name, "archiveBytes": archive.stat().st_size,
               "unpackedFileBytes": payload_bytes,
               "archiveSha256": digest(archive), "distributionSigned": False,
               "signingIdentityProvided": False,
               "runtimeTestsExecuted": False, "releaseAccepted": False}
    if selected == "ios-join":
        receipt["testOnlyJoinVariant"] = True
        receipt["joinTestingCompilationCondition"] = "NVPN_RELEASE_JOIN_TESTING"
        receipt["fixtureInfo"] = {key: values[key] for key in (
            "CFBundleDisplayName", "UIFileSharingEnabled", "LSSupportsOpeningDocumentsInPlace")}
    (output / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")


if __name__ == "__main__":
    main()
