#!/usr/bin/env python3
"""Hash and validate immutable mobile Release artifact receipts."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import plistlib
import stat
import sys
from typing import Any

IOS_FIXTURE_DISPLAY_NAME = "Nostr VPN Test Files"
IOS_FIXTURE_SCOPE = "join-test-variant-only"


def ios_fixture_identity(bundle: str) -> dict[str, Any]:
    return {
        "bundleIdentifier": bundle,
        "displayName": IOS_FIXTURE_DISPLAY_NAME,
        "scope": IOS_FIXTURE_SCOPE,
    }


def require_ios_fixture_info(info: dict[str, Any]) -> None:
    if (
        info.get("CFBundleDisplayName") != IOS_FIXTURE_DISPLAY_NAME
        or info.get("UIFileSharingEnabled") is not True
        or info.get("LSSupportsOpeningDocumentsInPlace") is not True
    ):
        raise ValueError("iOS join-test app lacks scoped Files fixture access")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: pathlib.Path) -> str:
    return sha256_bytes(path.read_bytes())


def path_sha256(path: pathlib.Path) -> str:
    return sha256_bytes(os.path.realpath(path).encode())


def symlink_entry(
    path: pathlib.Path, root: pathlib.Path, metadata: os.stat_result
) -> dict[str, Any]:
    target = os.readlink(path)
    resolved = (path.parent / target).resolve(strict=False)
    try:
        resolved.relative_to(root.resolve())
    except ValueError as error:
        raise ValueError(f"artifact symlink escapes its tree: {path}") from error
    return {
        "mode": stat.S_IMODE(metadata.st_mode),
        "path": path.relative_to(root).as_posix(),
        "target": target,
        "type": "symlink",
    }


def tree_sha256(root: pathlib.Path) -> str:
    if not root.is_dir():
        raise ValueError(f"tree root is not a directory: {root}")
    entries: list[dict[str, Any]] = []
    for current, directories, files in os.walk(root, followlinks=False):
        current_path = pathlib.Path(current)
        directories.sort()
        files.sort()
        retained_directories: list[str] = []
        for name in directories:
            path = current_path / name
            if path.is_symlink():
                metadata = path.lstat()
                entries.append(symlink_entry(path, root, metadata))
            else:
                retained_directories.append(name)
        directories[:] = retained_directories
        for name in files:
            path = current_path / name
            relative = path.relative_to(root).as_posix()
            metadata = path.lstat()
            if path.is_symlink():
                entries.append(symlink_entry(path, root, metadata))
                continue
            if not path.is_file():
                raise ValueError(f"unsupported artifact tree entry: {path}")
            entries.append(
                {
                    "mode": stat.S_IMODE(metadata.st_mode),
                    "path": relative,
                    "sha256": sha256_file(path),
                    "size": metadata.st_size,
                    "type": "file",
                }
            )
    canonical = json.dumps(
        entries, separators=(",", ":"), sort_keys=True
    ).encode()
    return sha256_bytes(canonical)


def load_json(path: pathlib.Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"JSON object required: {path}")
    return value


def require_equal(
    receipt: dict[str, Any], name: str, expected: Any
) -> None:
    actual = receipt.get(name)
    if actual != expected:
        raise ValueError(
            f"{name} mismatch: expected {expected!r}, got {actual!r}"
        )


def require_lower_hash(value: Any, name: str, length: int) -> str:
    if (
        not isinstance(value, str)
        or len(value) != length
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"{name} is not a lowercase {length}-character hash")
    return value


def artifact_source(args: argparse.Namespace) -> None:
    receipt = load_json(pathlib.Path(args.receipt))
    require_equal(receipt, "receiptSchema", 2)
    require_equal(receipt, "artifactType", args.artifact_type)
    head = require_lower_hash(receipt.get("appGitSha"), "appGitSha", 40)
    tree = require_lower_hash(receipt.get("appGitTree"), "appGitTree", 40)
    print(f"{head}\t{tree}")


def build_join_summary(args: argparse.Namespace) -> None:
    harness_head = require_lower_hash(
        args.harness_head, "harness commit", 40
    )
    harness_tree = require_lower_hash(args.harness_tree, "harness tree", 40)
    android_app_head = require_lower_hash(
        args.android_app_head, "Android application commit", 40
    )
    android_app_tree = require_lower_hash(
        args.android_app_tree, "Android application tree", 40
    )
    ios_app_head = require_lower_hash(
        args.ios_app_head, "iOS application commit", 40
    )
    ios_app_git_tree = require_lower_hash(
        args.ios_app_git_tree, "iOS application tree", 40
    )
    fips_head = require_lower_hash(args.fips_head, "FIPS commit", 40)
    fips_tree = require_lower_hash(args.fips_tree, "FIPS tree", 40)
    apk_sha = require_lower_hash(args.android_apk_sha, "Android APK", 64)
    ios_app_bundle_tree_sha = require_lower_hash(
        args.ios_app_bundle_tree_sha, "iOS app bundle tree", 64
    )
    qr_captures = {
        "androidRenderedScreenSha256": sha256_file(
            pathlib.Path(args.android_qr_capture)
        ),
        "iosRenderedScreenSha256": sha256_file(
            pathlib.Path(args.ios_qr_capture)
        ),
    }
    png_signature = b"\x89PNG\r\n\x1a\n"
    for path in (args.android_qr_capture, args.ios_qr_capture):
        if pathlib.Path(path).read_bytes()[:8] != png_signature:
            raise ValueError("mobile join QR screen capture is not a PNG")

    android_receipt_path = pathlib.Path(args.android_receipt)
    ios_receipt_path = pathlib.Path(args.ios_receipt)
    ios_production_receipt_path = pathlib.Path(args.ios_production_receipt)
    android = load_json(android_receipt_path)
    ios = load_json(ios_receipt_path)
    ios_production = load_json(ios_production_receipt_path)
    android_expected = {
        "receiptSchema": 2,
        "artifactType": "Android Release APK",
        "appGitSha": android_app_head,
        "appGitTree": android_app_tree,
        "fipsGitSha": fips_head,
        "fipsGitTree": fips_tree,
        "apkSha256": apk_sha,
        "installedApkSha256": apk_sha,
        "companySigningVerified": True,
    }
    ios_production_expected = {
        "receiptSchema": 2,
        "artifactType": "iOS company Ad Hoc Release app",
        "appGitSha": ios_app_head,
        "appGitTree": ios_app_git_tree,
        "fipsGitSha": fips_head,
        "fipsGitTree": fips_tree,
        "companySigningVerified": True,
    }
    ios_expected = {
        **ios_production_expected,
        "artifactType": "iOS Ad Hoc Release join-test variant",
        "appBundleTreeSha256": ios_app_bundle_tree_sha,
        "fileSharingFixture": ios_fixture_identity(
            ios_production["installedBundleIdentifier"]
        ),
        "joinTestingCompilationCondition": "NVPN_RELEASE_JOIN_TESTING",
        "joinTestingCompilationConditionEnabled": True,
        "productionArtifactReceiptSha256": sha256_file(
            ios_production_receipt_path
        ),
        "productionAppByteIdentical": False,
        "debuggable": False,
    }
    for name, value in android_expected.items():
        require_equal(android, name, value)
    for name, value in ios_expected.items():
        require_equal(ios, name, value)
    for name, value in ios_production_expected.items():
        require_equal(ios_production, name, value)

    android_identity_keys = (
        "apkSha256",
        "installedApkSha256",
        "package",
        "signerCertificateSha256",
    )
    ios_identity_keys = (
        "appBundleTreeSha256",
        "appCodeDirectoryHash",
        "packetTunnelCodeDirectoryHash",
        "appExecutableSha256",
        "packetTunnelExecutableSha256",
        "signerCertificateSha256",
        "installedBundleIdentifier",
        "fileSharingFixture",
    )
    for key in android_identity_keys:
        if not android.get(key):
            raise ValueError(f"Android join artifact lacks {key}")
    for key in ios_identity_keys:
        if not ios.get(key):
            raise ValueError(f"iOS join artifact lacks {key}")

    timings = {}
    for line in pathlib.Path(args.timings).read_text(
        encoding="utf-8"
    ).splitlines():
        label, elapsed = line.split("\t")
        timings[label] = int(elapsed)
    expected_timings = {
        "iPhone-admin-to-Pixel-QR",
        "Pixel-admin-to-iPhone-QR",
        "iPhone-admin-to-Pixel-manual",
        "Pixel-admin-to-iPhone-manual",
    }
    if set(timings) != expected_timings or any(
        elapsed < 0 or elapsed > 15_000 for elapsed in timings.values()
    ):
        raise ValueError(
            "mobile join delivery timing receipt is incomplete or slow"
        )
    minimum_width = 9_800
    maximum_width = 10_000
    widths = {
        "androidObservedBasisPoints": int(args.android_qr_width_bps),
        "iosObservedBasisPoints": int(args.ios_qr_width_bps),
    }
    if any(
        observed < minimum_width or observed > maximum_width
        for observed in widths.values()
    ):
        raise ValueError("mobile join QR did not fill its content width")
    lifecycle_values = (
        args.android_pending_qr_lifecycle_ready,
        args.ios_qr_relaunch_durable,
        args.ios_admin_manual_relaunch_durable,
        args.ios_joiner_manual_relaunch_durable,
    )
    if any(value != "1" for value in lifecycle_values):
        raise ValueError(
            "mobile QR lifecycle or iPhone directional relaunch evidence "
            "is incomplete"
        )
    result = {
        "schema": 1,
        "platform": "mobile",
        "coverageScope": "android-ios-mobile-only",
        "harnessGitSha": harness_head,
        "harnessGitTree": harness_tree,
        "artifact": {
            "fipsGitSha": fips_head,
            "fipsGitTree": fips_tree,
            "androidBuildType": "Release",
            "iosBuildType": "Release",
            "iosDistribution": "Ad Hoc",
            "android": {
                "artifactReceiptSha256": sha256_file(android_receipt_path),
                "appGitSha": android_app_head,
                "appGitTree": android_app_tree,
                "fipsGitSha": fips_head,
                "fipsGitTree": fips_tree,
                **{key: android[key] for key in android_identity_keys},
            },
            "ios": {
                "artifactReceiptSha256": sha256_file(ios_receipt_path),
                "productionArtifactReceiptSha256": sha256_file(
                    ios_production_receipt_path
                ),
                "joinTestingCompilationCondition": (
                    "NVPN_RELEASE_JOIN_TESTING"
                ),
                "joinTestingCompilationConditionEnabled": True,
                "productionAppByteIdentical": False,
                "appGitSha": ios_app_head,
                "appGitTree": ios_app_git_tree,
                "fipsGitSha": fips_head,
                "fipsGitTree": fips_tree,
                **{key: ios[key] for key in ios_identity_keys},
            },
        },
        "publicUiOnly": True,
        "productionImageImportQr": False,
        "iosJoinTestVariant": True,
        "testOnlyImageImportQr": True,
        "productionQrDecoderPath": True,
        "productionJoinApprovalPath": True,
        "productionRosterPath": True,
        "actualRenderedQrScreenCapture": qr_captures,
        "privateAppStateRead": False,
        "appLaunchArgumentsOrEnvironment": False,
        "deliveryDeadlineMilliseconds": 15_000,
        "contentWidth": {
            "minimumRequiredBasisPoints": minimum_width,
            "maximumAllowedBasisPoints": maximum_width,
            **widths,
        },
        "qr": {
            "iphoneAdminPixelJoiner": True,
            "pixelAdminIphoneJoiner": True,
            "pendingQrBackgroundForeground": True,
            "exactRosterOnBothSides": True,
            "joinerRelaunchDurable": True,
            "androidJoinerRelaunchDurable": True,
            "iphoneJoinerRelaunchDurable": True,
        },
        "manual": {
            "iphoneAdminPixelJoiner": True,
            "pixelAdminIphoneJoiner": True,
            "exactRosterOnBothSides": True,
            "acceptedRosterOnly": True,
            "iphoneAdminPixelJoinerRelaunchDurable": True,
            "pixelAdminIphoneJoinerRelaunchDurable": True,
        },
        "deliveryMilliseconds": timings,
    }
    pathlib.Path(args.summary).write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def validate_fips_metadata(
    path: pathlib.Path,
    checkout_path_sha: str,
    head: str,
    tree: str,
    version: str,
) -> None:
    metadata = load_json(path)
    require_equal(metadata, "checkoutPathSha256", checkout_path_sha)
    require_equal(metadata, "checkoutHead", head)
    require_equal(metadata, "checkoutTree", tree)
    require_equal(metadata, "fipsCoreVersion", version)


def validate_android(args: argparse.Namespace) -> None:
    receipt_path = pathlib.Path(args.receipt)
    apk = pathlib.Path(args.apk)
    metadata = pathlib.Path(args.fips_metadata)
    app_root = pathlib.Path(args.app_root)
    fips_root = pathlib.Path(args.fips_root)
    for path in (receipt_path, apk, metadata):
        if not path.is_file() or path.is_symlink():
            raise ValueError(f"required Android artifact is missing: {path}")
    receipt = load_json(receipt_path)
    apk_sha = sha256_file(apk)
    expected = {
        "receiptSchema": 2,
        "artifactType": "Android Release APK",
        "apkSha256": apk_sha,
        "installedApkSha256": apk_sha,
        "companySigningVerified": True,
        "signerCertificateSha256": args.signer_sha,
        "appGitSha": args.app_head,
        "appGitTree": args.app_tree,
        "fipsGitSha": args.fips_head,
        "fipsGitTree": args.fips_tree,
        "fipsCoreVersion": args.fips_version,
        "fipsCargoMetadataReceiptSha256": sha256_file(metadata),
        "fipsDependenciesForcedRebuilt": True,
        "package": args.package,
        "replacementInstall": True,
        "debuggable": False,
    }
    for name, value in expected.items():
        require_equal(receipt, name, value)
    for name in (
        "apkPathSha256",
        "fipsCheckoutPathSha256",
        "fipsCargoMetadataReceiptPathSha256",
    ):
        require_lower_hash(receipt.get(name), name, 64)
    aab_value = getattr(args, "aab", None)
    bundle_value = getattr(args, "bundle_receipt", None)
    if bool(aab_value) != bool(bundle_value):
        raise ValueError(
            "Android AAB and physical-gate receipt must be supplied together"
        )
    if aab_value:
        aab = pathlib.Path(aab_value)
        bundle_path = pathlib.Path(bundle_value)
        for path in (aab, bundle_path):
            if not path.is_file() or path.is_symlink():
                raise ValueError(
                    f"exact Android artifact must be a regular file: {path}"
                )
        bundle = load_json(bundle_path)
        aab_sha = sha256_file(aab)
        bundle_sha = sha256_file(bundle_path)
        bundletool_version = "1.18.3"
        bundletool_sha = (
            "a099cfa1543f55593bc2ed16a70a7c67fe54b1747bb7301f37fdfd6d91028e29"
        )
        bundle_expected = {
            "schema": 1,
            "relationship": "universal-apk-derived-from-exact-aab",
            "appGitSha": args.app_head,
            "appGitTree": args.app_tree,
            "aabSha256": aab_sha,
            "apkSha256": apk_sha,
            "bundletoolVersion": bundletool_version,
            "bundletoolSha256": bundletool_sha,
        }
        for name, value in bundle_expected.items():
            require_equal(bundle, name, value)
        require_lower_hash(bundle.get("aabPathSha256"), "aabPathSha256", 64)
        require_equal(
            bundle,
            "apkPathSha256",
            receipt["apkPathSha256"],
        )
        relationship_expected = {
            "aabSha256": aab_sha,
            "apkDerivedFromAab": True,
            "bundleReceiptSha256": bundle_sha,
            "bundletoolVersion": bundletool_version,
            "bundletoolSha256": bundletool_sha,
        }
        for name, value in relationship_expected.items():
            require_equal(receipt, name, value)
    if args.actual_package != args.package:
        raise ValueError(
            "Android APK package mismatch: "
            f"expected {args.package!r}, got {args.actual_package!r}"
        )
    if path_sha256(app_root) == path_sha256(fips_root):
        raise ValueError("application and FIPS checkouts unexpectedly coincide")
    validate_fips_metadata(
        metadata,
        receipt["fipsCheckoutPathSha256"],
        args.fips_head,
        args.fips_tree,
        args.fips_version,
    )


def validate_xctestrun(path: pathlib.Path) -> None:
    payload = plistlib.load(path.open("rb"))
    if not isinstance(payload, dict):
        raise ValueError("iOS xctestrun root is not a dictionary")
    targets = []
    legacy = payload.get("NostrVpnIosUITests")
    if isinstance(legacy, dict):
        targets.append(legacy)
    configurations = payload.get("TestConfigurations")
    if isinstance(configurations, list):
        for configuration in configurations:
            if not isinstance(configuration, dict):
                continue
            for target in configuration.get("TestTargets", []):
                if isinstance(target, dict) and (
                    target.get("BlueprintName") == "NostrVpnIosUITests"
                    or target.get("ProductModuleName")
                    == "NostrVpnIosUITests"
                ):
                    targets.append(target)
    if not targets:
        raise ValueError("iOS xctestrun lacks NostrVpnIosUITests")
    for target in targets:
        for key in ("TestBundlePath", "TestHostPath", "UITargetAppPath"):
            value = target.get(key)
            if not isinstance(value, str) or not value:
                raise ValueError(f"iOS xctestrun lacks {key}")


def create_ios_join_variant(args: argparse.Namespace) -> None:
    for value, name, length in (
        (args.app_head, "application commit", 40),
        (args.app_tree, "application tree", 40),
        (args.fips_head, "FIPS commit", 40),
        (args.fips_tree, "FIPS tree", 40),
        (args.signer_sha, "signer certificate", 64),
        (args.app_cdhash, "app code-directory hash", 40),
        (args.tunnel_cdhash, "tunnel code-directory hash", 40),
        (args.device_identifier_sha, "device identifier", 64),
    ):
        require_lower_hash(value, name, length)
    output = pathlib.Path(args.receipt)
    production_path = pathlib.Path(args.production_receipt)
    app = pathlib.Path(args.app)
    derived = pathlib.Path(args.derived_data)
    xctestrun = pathlib.Path(args.xctestrun)
    products = derived / "Build" / "Products"
    tunnel_app = app / "PlugIns" / "Nostr VPN Tunnel.appex"
    executable = app / "Nostr VPN"
    tunnel_executable = tunnel_app / "Nostr VPN Tunnel"
    app_profile = app / "embedded.mobileprovision"
    tunnel_profile = tunnel_app / "embedded.mobileprovision"
    info = app / "Info.plist"
    for path in (
        production_path,
        xctestrun,
        executable,
        tunnel_executable,
        app_profile,
        tunnel_profile,
        info,
    ):
        if not path.is_file() or path.is_symlink():
            raise ValueError(f"required iOS artifact is missing: {path}")
    for path in (app, derived, products, tunnel_app):
        if not path.is_dir() or path.is_symlink():
            raise ValueError(f"required iOS artifact tree is missing: {path}")
    app_info = plistlib.load(info.open("rb"))
    if app_info.get("CFBundleIdentifier") != args.bundle:
        raise ValueError("iOS app bundle identifier mismatch")
    require_ios_fixture_info(app_info)
    validate_xctestrun(xctestrun)

    production = load_json(production_path)
    production_identity = {
        "receiptSchema": 2,
        "artifactType": "iOS company Ad Hoc Release app",
        "appGitSha": args.app_head,
        "appGitTree": args.app_tree,
        "fipsGitSha": args.fips_head,
        "fipsGitTree": args.fips_tree,
        "fipsCoreVersion": args.fips_version,
        "companySigningVerified": True,
        "signerCertificateSha256": args.signer_sha,
        "selectedPhysicalDeviceIdentifierSha256": args.device_identifier_sha,
        "installedBundleIdentifier": args.bundle,
        "debuggable": False,
    }
    for name, value in production_identity.items():
        require_equal(production, name, value)
    selected_device = production.get("selectedPhysicalDevice")
    if not isinstance(selected_device, dict):
        raise ValueError("production iOS receipt has no selected physical device")
    require_equal(
        selected_device,
        "deviceIdentifierSha256",
        args.device_identifier_sha,
    )
    require_equal(selected_device, "explicitPhysicalDeviceVerified", True)
    require_equal(selected_device, "platform", "iOS")
    if not selected_device.get("model") or not selected_device.get("productType"):
        raise ValueError("production iOS receipt has incomplete device metadata")

    app_tree = tree_sha256(app)
    app_executable_sha = sha256_file(executable)
    if app_tree == production.get("appBundleTreeSha256"):
        raise ValueError("join-test app bundle tree matches production")
    if app_executable_sha == production.get("appExecutableSha256"):
        raise ValueError("join-test app executable matches production")
    if args.app_cdhash == production.get("appCodeDirectoryHash"):
        raise ValueError("join-test app code-directory hash matches production")

    receipt = dict(production)
    receipt.update(
        {
            **production_identity,
            "artifactType": "iOS Ad Hoc Release join-test variant",
            "appCodeDirectoryHash": args.app_cdhash,
            "packetTunnelCodeDirectoryHash": args.tunnel_cdhash,
            "appExecutableSha256": app_executable_sha,
            "packetTunnelExecutableSha256": sha256_file(tunnel_executable),
            "appPathSha256": path_sha256(app),
            "appBundleTreeSha256": app_tree,
            "treeSha256": app_tree,
            "derivedDataPathSha256": path_sha256(derived),
            "testProductsPathSha256": path_sha256(products),
            "testProductsTreeSha256": tree_sha256(products),
            "xctestrunPathSha256": path_sha256(xctestrun),
            "xctestrunSha256": sha256_file(xctestrun),
            "appProvisioningProfileSha256": sha256_file(app_profile),
            "packetTunnelProvisioningProfileSha256": sha256_file(
                tunnel_profile
            ),
            "selectedPhysicalDevice": selected_device,
            "fileSharingFixture": ios_fixture_identity(args.bundle),
            "joinTestingCompilationCondition": (
                "NVPN_RELEASE_JOIN_TESTING"
            ),
            "joinTestingCompilationConditionEnabled": True,
            "productionArtifactReceiptSha256": sha256_file(
                production_path
            ),
            "productionAppByteIdentical": False,
        }
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def validate_ios(args: argparse.Namespace) -> None:
    receipt_path = pathlib.Path(args.receipt)
    app = pathlib.Path(args.app)
    derived = pathlib.Path(args.derived_data)
    xctestrun = pathlib.Path(args.xctestrun)
    metadata = pathlib.Path(args.fips_metadata)
    fips_root = pathlib.Path(args.fips_root)
    products = derived / "Build" / "Products"
    tunnel_app = app / "PlugIns" / "Nostr VPN Tunnel.appex"
    executable = app / "Nostr VPN"
    tunnel_executable = tunnel_app / "Nostr VPN Tunnel"
    app_profile = app / "embedded.mobileprovision"
    tunnel_profile = tunnel_app / "embedded.mobileprovision"
    info = app / "Info.plist"
    for path in (
        receipt_path,
        xctestrun,
        metadata,
        executable,
        tunnel_executable,
        app_profile,
        tunnel_profile,
        info,
    ):
        if not path.is_file():
            raise ValueError(f"required iOS artifact is missing: {path}")
    for path in (app, derived, products, tunnel_app):
        if not path.is_dir():
            raise ValueError(f"required iOS artifact tree is missing: {path}")
    app_info = plistlib.load(info.open("rb"))
    if app_info.get("CFBundleIdentifier") != args.bundle:
        raise ValueError("iOS app bundle identifier mismatch")
    validate_xctestrun(xctestrun)
    receipt = load_json(receipt_path)
    app_tree = tree_sha256(app)
    products_tree = tree_sha256(products)
    production_receipt_path = (
        pathlib.Path(args.production_receipt)
        if args.production_receipt
        else None
    )
    artifact_type = (
        "iOS Ad Hoc Release join-test variant"
        if production_receipt_path
        else "iOS company Ad Hoc Release app"
    )
    expected = {
        "receiptSchema": 2,
        "artifactType": artifact_type,
        "appCodeDirectoryHash": args.app_cdhash,
        "packetTunnelCodeDirectoryHash": args.tunnel_cdhash,
        "appExecutableSha256": sha256_file(executable),
        "packetTunnelExecutableSha256": sha256_file(tunnel_executable),
        "appGitSha": args.app_head,
        "appGitTree": args.app_tree,
        "appPathSha256": path_sha256(app),
        "appBundleTreeSha256": app_tree,
        "treeSha256": app_tree,
        "derivedDataPathSha256": path_sha256(derived),
        "testProductsPathSha256": path_sha256(products),
        "testProductsTreeSha256": products_tree,
        "xctestrunPathSha256": path_sha256(xctestrun),
        "xctestrunSha256": sha256_file(xctestrun),
        "fipsGitSha": args.fips_head,
        "fipsGitTree": args.fips_tree,
        "fipsCoreVersion": args.fips_version,
        "fipsCargoMetadataReceiptPathSha256": path_sha256(metadata),
        "fipsCargoMetadataReceiptSha256": sha256_file(metadata),
        "fipsDependenciesForcedRebuilt": True,
        "appProvisioningProfileSha256": sha256_file(app_profile),
        "packetTunnelProvisioningProfileSha256": sha256_file(tunnel_profile),
        "companySigningVerified": True,
        "signerCertificateSha256": args.signer_sha,
        "selectedPhysicalDeviceIdentifierSha256": args.device_identifier_sha,
        "installedBundleIdentifier": args.bundle,
        "cashuAndPaidExitCompiled": False,
        "paidExitWalletWorkerCompiled": False,
        "updaterCompiled": False,
        "debuggable": False,
    }
    if production_receipt_path:
        require_ios_fixture_info(app_info)
        production = load_json(production_receipt_path)
        for name, value in {
            "receiptSchema": 2,
            "artifactType": "iOS company Ad Hoc Release app",
            "appGitSha": args.app_head,
            "appGitTree": args.app_tree,
            "fipsGitSha": args.fips_head,
            "fipsGitTree": args.fips_tree,
            "companySigningVerified": True,
        }.items():
            require_equal(production, name, value)
        expected.update(
            {
                "joinTestingCompilationCondition": (
                    "NVPN_RELEASE_JOIN_TESTING"
                ),
                "joinTestingCompilationConditionEnabled": True,
                "fileSharingFixture": ios_fixture_identity(args.bundle),
                "productionArtifactReceiptSha256": sha256_file(
                    production_receipt_path
                ),
                "productionAppByteIdentical": False,
            }
        )
    elif (
        "UIFileSharingEnabled" in app_info
        or "LSSupportsOpeningDocumentsInPlace" in app_info
    ):
        raise ValueError("production iOS app exposes test fixture file sharing")
    for name, value in expected.items():
        require_equal(receipt, name, value)
    require_lower_hash(
        receipt.get("fipsCheckoutPathSha256"),
        "fipsCheckoutPathSha256",
        64,
    )
    device = receipt.get("selectedPhysicalDevice")
    if not isinstance(device, dict):
        raise ValueError("iOS receipt has no selected physical device")
    require_equal(device, "explicitPhysicalDeviceVerified", True)
    require_equal(device, "deviceIdentifierSha256", args.device_identifier_sha)
    require_equal(device, "platform", "iOS")
    if not device.get("model") or not device.get("productType"):
        raise ValueError("iOS receipt has incomplete selected-device metadata")
    validate_fips_metadata(
        metadata,
        receipt["fipsCheckoutPathSha256"],
        args.fips_head,
        args.fips_tree,
        args.fips_version,
    )


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    subparsers = result.add_subparsers(dest="command", required=True)
    tree = subparsers.add_parser("tree-sha")
    tree.add_argument("path")

    source = subparsers.add_parser("artifact-source")
    source.add_argument("--receipt", required=True)
    source.add_argument("--artifact-type", required=True)

    summary = subparsers.add_parser("join-summary")
    for name in (
        "summary",
        "timings",
        "harness_head",
        "harness_tree",
        "android_app_head",
        "android_app_tree",
        "ios_app_head",
        "ios_app_git_tree",
        "fips_head",
        "fips_tree",
        "android_apk_sha",
        "android_receipt",
        "ios_app_bundle_tree_sha",
        "ios_receipt",
        "ios_production_receipt",
        "android_qr_capture",
        "ios_qr_capture",
        "android_qr_width_bps",
        "android_pending_qr_lifecycle_ready",
        "ios_qr_width_bps",
        "ios_qr_relaunch_durable",
        "ios_admin_manual_relaunch_durable",
        "ios_joiner_manual_relaunch_durable",
    ):
        summary.add_argument(f"--{name.replace('_', '-')}", required=True)

    android = subparsers.add_parser("validate-android")
    for name in (
        "receipt",
        "apk",
        "fips_metadata",
        "app_root",
        "fips_root",
        "app_head",
        "app_tree",
        "fips_head",
        "fips_tree",
        "fips_version",
        "package",
        "actual_package",
        "signer_sha",
    ):
        android.add_argument(f"--{name.replace('_', '-')}", required=True)
    android.add_argument("--aab")
    android.add_argument("--bundle-receipt")

    ios = subparsers.add_parser("validate-ios")
    for name in (
        "receipt",
        "app",
        "derived_data",
        "xctestrun",
        "fips_metadata",
        "fips_root",
        "app_head",
        "app_tree",
        "fips_head",
        "fips_tree",
        "fips_version",
        "bundle",
        "signer_sha",
        "app_cdhash",
        "tunnel_cdhash",
        "device_identifier_sha",
    ):
        ios.add_argument(f"--{name.replace('_', '-')}", required=True)
    ios.add_argument("--production-receipt")

    variant = subparsers.add_parser("create-ios-join-variant")
    for name in (
        "receipt",
        "production_receipt",
        "app",
        "derived_data",
        "xctestrun",
        "app_head",
        "app_tree",
        "fips_head",
        "fips_tree",
        "fips_version",
        "bundle",
        "signer_sha",
        "app_cdhash",
        "tunnel_cdhash",
        "device_identifier_sha",
    ):
        variant.add_argument(f"--{name.replace('_', '-')}", required=True)
    return result


def main() -> int:
    args = parser().parse_args()
    try:
        if args.command == "tree-sha":
            print(tree_sha256(pathlib.Path(args.path)))
        elif args.command == "artifact-source":
            artifact_source(args)
        elif args.command == "join-summary":
            build_join_summary(args)
        elif args.command == "validate-android":
            validate_android(args)
        elif args.command == "validate-ios":
            validate_ios(args)
        elif args.command == "create-ios-join-variant":
            create_ios_join_variant(args)
        else:
            raise ValueError(f"unsupported command: {args.command}")
    except (OSError, ValueError, json.JSONDecodeError, plistlib.InvalidFileException) as error:
        print(f"mobile Release artifact receipt rejected: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
