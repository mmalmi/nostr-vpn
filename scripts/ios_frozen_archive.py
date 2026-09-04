#!/usr/bin/env python3
"""Freeze, compare, and prove one iOS archive across physical and store exports."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import plistlib
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from typing import Any

from mobile_release_artifact_receipt import (
    load_json,
    path_sha256,
    sha256_file,
    tree_sha256,
    validate_fips_metadata,
)
from ios_xctestrun import rewrite_xctestrun
from ios_frozen_gate import seal_gate, validate_gate_seal


APP_NAME = "Nostr VPN.app"
APP_EXECUTABLE = "Nostr VPN"
TUNNEL_NAME = "Nostr VPN Tunnel.appex"
TUNNEL_EXECUTABLE = "Nostr VPN Tunnel"
RECEIPT_SCHEMA = 1


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def run(
    command: list[str],
    *,
    input_bytes: bytes | None = None,
    stderr_to_stdout: bool = False,
) -> bytes:
    result = subprocess.run(
        command,
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT if stderr_to_stdout else subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        detail = (
            result.stdout
            if stderr_to_stdout
            else (result.stderr or result.stdout)
        ).decode("utf-8", errors="replace").strip()
        raise ValueError(f"{' '.join(command)} failed: {detail}")
    return result.stdout


def atomic_json(path: pathlib.Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=path.parent
    )
    temporary = pathlib.Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def normalized_executable_sha256(path: pathlib.Path) -> str:
    require(path.is_file(), f"signed executable is missing: {path}")
    with tempfile.TemporaryDirectory(prefix="nvpn-ios-unsigned-") as temporary:
        unsigned = pathlib.Path(temporary) / path.name
        shutil.copy2(path, unsigned)
        run(["codesign", "--remove-signature", str(unsigned)])
        return sha256_file(unsigned)


def safe_symlink(path: pathlib.Path, root: pathlib.Path) -> dict[str, Any]:
    target = os.readlink(path)
    resolved = (path.parent / target).resolve(strict=False)
    try:
        resolved.relative_to(root.resolve())
    except ValueError as error:
        raise ValueError(f"iOS bundle symlink escapes its root: {path}") from error
    return {
        "path": path.relative_to(root).as_posix(),
        "target": target,
        "type": "symlink",
    }


def canonical_plist(path: pathlib.Path) -> bytes:
    return plistlib.dumps(
        read_plist(path),
        fmt=plistlib.FMT_BINARY,
        sort_keys=True,
    )


def unsigned_content_manifest(
    app: pathlib.Path,
    *,
    canonicalize_plists: bool = False,
) -> tuple[str, int]:
    excluded_files = {
        pathlib.PurePosixPath(APP_EXECUTABLE),
        pathlib.PurePosixPath("embedded.mobileprovision"),
        pathlib.PurePosixPath("PlugIns") / TUNNEL_NAME / TUNNEL_EXECUTABLE,
        pathlib.PurePosixPath("PlugIns") / TUNNEL_NAME / "embedded.mobileprovision",
    }
    semantic_plists = {
        pathlib.PurePosixPath("Info.plist"),
        pathlib.PurePosixPath("PlugIns") / TUNNEL_NAME / "Info.plist",
    }
    entries: list[dict[str, Any]] = []
    for current, directories, files in os.walk(app, followlinks=False):
        current_path = pathlib.Path(current)
        directories.sort()
        files.sort()
        retained: list[str] = []
        for name in directories:
            path = current_path / name
            relative = path.relative_to(app)
            if name == "_CodeSignature":
                continue
            if path.is_symlink():
                entries.append(safe_symlink(path, app))
                continue
            if relative != pathlib.Path("PlugIns") / TUNNEL_NAME and (
                name.endswith((".app", ".appex", ".framework"))
            ):
                raise ValueError(f"unexpected nested iOS code bundle: {relative}")
            retained.append(name)
        directories[:] = retained
        for name in files:
            path = current_path / name
            relative = pathlib.PurePosixPath(path.relative_to(app).as_posix())
            if relative in excluded_files:
                continue
            metadata = path.lstat()
            if path.is_symlink():
                entries.append(safe_symlink(path, app))
                continue
            require(path.is_file(), f"unsupported iOS bundle entry: {path}")
            if name.endswith((".dylib", ".so")):
                raise ValueError(f"unexpected nested iOS executable: {relative}")
            content = (
                canonical_plist(path)
                if canonicalize_plists and relative in semantic_plists
                else None
            )
            entries.append(
                {
                    "mode": stat.S_IMODE(metadata.st_mode),
                    "path": relative.as_posix(),
                    "sha256": (
                        hashlib.sha256(content).hexdigest()
                        if content is not None
                        else sha256_file(path)
                    ),
                    "size": len(content) if content is not None else metadata.st_size,
                    "type": "file",
                }
            )
    canonical = json.dumps(
        entries, separators=(",", ":"), sort_keys=True
    ).encode()
    return hashlib.sha256(canonical).hexdigest(), len(entries)


def read_plist(path: pathlib.Path) -> dict[str, Any]:
    require(path.is_file(), f"property list is missing: {path}")
    value = plistlib.load(path.open("rb"))
    require(isinstance(value, dict), f"property list root is not a dictionary: {path}")
    return value


def app_paths(app: pathlib.Path) -> dict[str, pathlib.Path]:
    tunnel = app / "PlugIns" / TUNNEL_NAME
    paths = {
        "app": app,
        "appExecutable": app / APP_EXECUTABLE,
        "appInfo": app / "Info.plist",
        "appProfile": app / "embedded.mobileprovision",
        "tunnel": tunnel,
        "tunnelExecutable": tunnel / TUNNEL_EXECUTABLE,
        "tunnelInfo": tunnel / "Info.plist",
        "tunnelProfile": tunnel / "embedded.mobileprovision",
    }
    for name, path in paths.items():
        if name in {"app", "tunnel"}:
            require(path.is_dir(), f"iOS bundle is missing: {path}")
        else:
            require(path.is_file(), f"iOS bundle file is missing: {path}")
    return paths


def bundle_identity(app: pathlib.Path) -> dict[str, Any]:
    paths = app_paths(app)
    app_info = read_plist(paths["appInfo"])
    tunnel_info = read_plist(paths["tunnelInfo"])
    content_sha, content_count = unsigned_content_manifest(app)
    return {
        "appBundleIdentifier": str(app_info.get("CFBundleIdentifier", "")),
        "appBuildGitSha": str(app_info.get("NVPNBuildGitSha", "")),
        "appBuildTimestampUTC": str(app_info.get("NVPNBuildTimestampUTC", "")),
        "appNormalizedExecutableSha256": normalized_executable_sha256(
            paths["appExecutable"]
        ),
        "buildNumber": str(app_info.get("CFBundleVersion", "")),
        "marketingVersion": str(
            app_info.get("CFBundleShortVersionString", "")
        ),
        "packetTunnelBundleIdentifier": str(
            tunnel_info.get("CFBundleIdentifier", "")
        ),
        "packetTunnelBuildGitSha": str(
            tunnel_info.get("NVPNBuildGitSha", "")
        ),
        "packetTunnelBuildTimestampUTC": str(
            tunnel_info.get("NVPNBuildTimestampUTC", "")
        ),
        "packetTunnelBuildNumber": str(
            tunnel_info.get("CFBundleVersion", "")
        ),
        "packetTunnelMarketingVersion": str(
            tunnel_info.get("CFBundleShortVersionString", "")
        ),
        "packetTunnelNormalizedExecutableSha256": normalized_executable_sha256(
            paths["tunnelExecutable"]
        ),
        "unsignedContentFileCount": content_count,
        "unsignedContentManifestSha256": content_sha,
    }


def export_equivalence_identity(app: pathlib.Path) -> dict[str, Any]:
    identity = bundle_identity(app)
    content_sha, content_count = unsigned_content_manifest(
        app,
        canonicalize_plists=True,
    )
    identity["unsignedContentFileCount"] = content_count
    identity["unsignedContentManifestSha256"] = content_sha
    return identity


def codesign_details(bundle: pathlib.Path) -> dict[str, str]:
    output = run(
        ["codesign", "-dvvv", str(bundle)], stderr_to_stdout=True
    ).decode("utf-8", errors="replace")
    values: dict[str, str] = {}
    for key in ("CDHash", "Identifier", "TeamIdentifier"):
        match = re.search(rf"^{key}=(.+)$", output, flags=re.MULTILINE)
        require(match is not None, f"codesign output lacks {key}: {bundle}")
        values[key] = match.group(1).strip()
    return values


def certificate_sha256(bundle: pathlib.Path) -> str:
    with tempfile.TemporaryDirectory(prefix="nvpn-ios-certificate-") as temporary:
        prefix = pathlib.Path(temporary) / "certificate"
        run(
            [
                "codesign",
                "-d",
                f"--extract-certificates={prefix}",
                str(bundle),
            ]
        )
        certificate = pathlib.Path(f"{prefix}0")
        require(certificate.is_file(), f"codesign returned no certificate: {bundle}")
        return sha256_file(certificate)


def decoded_profile(path: pathlib.Path) -> dict[str, Any]:
    value = plistlib.loads(
        run(["security", "cms", "-D", "-i", str(path)])
    )
    require(
        isinstance(value, dict),
        f"provisioning profile is malformed: {path}",
    )
    return value


def signed_entitlements(bundle: pathlib.Path) -> dict[str, Any]:
    output = run(
        ["codesign", "-d", "--entitlements", ":-", str(bundle)]
    )
    value = plistlib.loads(output)
    require(isinstance(value, dict), f"signed entitlements are malformed: {bundle}")
    return value


def validate_profile(
    profile: dict[str, Any],
    entitlements: dict[str, Any],
    *,
    distribution: str,
    team_id: str,
    bundle_id: str,
    app_group_id: str,
    signer_sha: str,
    device_udid: str,
) -> None:
    profile_entitlements = profile.get("Entitlements")
    require(
        isinstance(profile_entitlements, dict),
        f"provisioning profile lacks entitlements: {bundle_id}",
    )
    require(
        profile.get("TeamIdentifier") == [team_id],
        f"provisioning profile has the wrong team: {bundle_id}",
    )
    require(
        profile_entitlements.get("com.apple.developer.team-identifier")
        == team_id,
        f"provisioning profile entitlement has the wrong team: {bundle_id}",
    )
    require(
        profile_entitlements.get("application-identifier")
        == f"{team_id}.{bundle_id}",
        f"provisioning profile has the wrong application identifier: {bundle_id}",
    )
    require(
        profile_entitlements.get("get-task-allow") is not True,
        f"provisioning profile is debuggable: {bundle_id}",
    )
    profile_groups = profile_entitlements.get(
        "com.apple.security.application-groups"
    )
    require(
        isinstance(profile_groups, list) and app_group_id in profile_groups,
        f"provisioning profile lacks the shared app group: {bundle_id}",
    )
    signers = {
        hashlib.sha256(value).hexdigest()
        for value in profile.get("DeveloperCertificates", [])
        if isinstance(value, bytes)
    }
    require(
        signer_sha in signers,
        f"provisioning profile does not authorize the pinned signer: {bundle_id}",
    )
    provisioned_devices = profile.get("ProvisionedDevices")
    if distribution == "release-testing":
        require(
            isinstance(provisioned_devices, list) and provisioned_devices,
            f"release-testing profile has no devices: {bundle_id}",
        )
        require(
            device_udid in provisioned_devices,
            f"release-testing profile omits the selected phone: {bundle_id}",
        )
        require(
            profile.get("ProvisionsAllDevices") is not True,
            f"release-testing profile is an enterprise profile: {bundle_id}",
        )
    else:
        require(
            not provisioned_devices,
            f"App Store profile unexpectedly provisions devices: {bundle_id}",
        )
        require(
            profile.get("ProvisionsAllDevices") is not True,
            f"App Store profile is an enterprise profile: {bundle_id}",
        )
    require(
        entitlements.get("get-task-allow") is not True,
        f"signed app is debuggable: {bundle_id}",
    )
    require(
        entitlements.get("com.apple.developer.team-identifier") == team_id,
        f"signed app has the wrong team entitlement: {bundle_id}",
    )
    require(
        entitlements.get("application-identifier")
        == f"{team_id}.{bundle_id}",
        f"signed app has the wrong application identifier: {bundle_id}",
    )
    signed_groups = entitlements.get("com.apple.security.application-groups")
    require(
        isinstance(signed_groups, list) and app_group_id in signed_groups,
        f"signed app lacks the shared app group: {bundle_id}",
    )


def signed_bundle_audit(
    app: pathlib.Path,
    *,
    distribution: str,
    team_id: str,
    signer_sha: str,
    app_bundle_id: str,
    tunnel_bundle_id: str,
    app_group_id: str,
    device_udid: str,
) -> dict[str, Any]:
    require(
        distribution in {"release-testing", "app-store-connect"},
        f"unsupported iOS distribution: {distribution}",
    )
    signer_sha = signer_sha.replace(":", "").strip().lower()
    require(
        re.fullmatch(r"[0-9a-f]{64}", signer_sha) is not None,
        "expected iOS signer SHA-256 is invalid",
    )
    paths = app_paths(app)
    run(["codesign", "--verify", "--deep", "--strict", str(app)])
    run(["codesign", "--verify", "--strict", str(paths["tunnel"])])
    app_details = codesign_details(app)
    tunnel_details = codesign_details(paths["tunnel"])
    require(
        app_details["Identifier"] == app_bundle_id,
        "signed app has the wrong bundle identifier",
    )
    require(
        tunnel_details["Identifier"] == tunnel_bundle_id,
        "signed Packet Tunnel has the wrong bundle identifier",
    )
    require(
        app_details["TeamIdentifier"] == team_id
        and tunnel_details["TeamIdentifier"] == team_id,
        "signed app or Packet Tunnel has the wrong team",
    )
    app_signer = certificate_sha256(app)
    tunnel_signer = certificate_sha256(paths["tunnel"])
    require(
        app_signer == signer_sha and tunnel_signer == signer_sha,
        "signed app or Packet Tunnel has the wrong certificate",
    )
    app_profile = decoded_profile(paths["appProfile"])
    tunnel_profile = decoded_profile(paths["tunnelProfile"])
    app_entitlements = signed_entitlements(app)
    tunnel_entitlements = signed_entitlements(paths["tunnel"])
    validate_profile(
        app_profile,
        app_entitlements,
        distribution=distribution,
        team_id=team_id,
        bundle_id=app_bundle_id,
        app_group_id=app_group_id,
        signer_sha=signer_sha,
        device_udid=device_udid,
    )
    validate_profile(
        tunnel_profile,
        tunnel_entitlements,
        distribution=distribution,
        team_id=team_id,
        bundle_id=tunnel_bundle_id,
        app_group_id=app_group_id,
        signer_sha=signer_sha,
        device_udid=device_udid,
    )
    app_network_extensions = app_entitlements.get(
        "com.apple.developer.networking.networkextension"
    )
    tunnel_network_extensions = tunnel_entitlements.get(
        "com.apple.developer.networking.networkextension"
    )
    require(
        isinstance(app_network_extensions, list)
        and "packet-tunnel-provider" in app_network_extensions,
        "signed app lacks its Network Extension entitlement",
    )
    require(
        isinstance(tunnel_network_extensions, list)
        and "packet-tunnel-provider" in tunnel_network_extensions,
        "signed Packet Tunnel lacks its Network Extension entitlement",
    )
    return {
        "appCodeDirectoryHash": app_details["CDHash"].lower(),
        "appGroupIdentifier": app_group_id,
        "appNetworkExtensionEntitlements": sorted(app_network_extensions),
        "appProvisioningProfileSha256": sha256_file(paths["appProfile"]),
        "packetTunnelCodeDirectoryHash": tunnel_details["CDHash"].lower(),
        "packetTunnelNetworkExtensionEntitlements": sorted(
            tunnel_network_extensions
        ),
        "packetTunnelProvisioningProfileSha256": sha256_file(
            paths["tunnelProfile"]
        ),
        "signerCertificateSha256": signer_sha,
        "signingTeamIdentifier": team_id,
    }


def validate_identity(
    identity: dict[str, Any],
    *,
    app_head: str,
    version: str,
    build: str,
    app_bundle_id: str,
    tunnel_bundle_id: str,
) -> None:
    expected = {
        "appBundleIdentifier": app_bundle_id,
        "appBuildGitSha": app_head,
        "buildNumber": build,
        "marketingVersion": version,
        "packetTunnelBundleIdentifier": tunnel_bundle_id,
        "packetTunnelBuildGitSha": app_head,
        "packetTunnelBuildNumber": build,
        "packetTunnelMarketingVersion": version,
    }
    for name, value in expected.items():
        require(
            identity.get(name) == value,
            f"iOS artifact {name} mismatch: expected {value!r}, "
            f"got {identity.get(name)!r}",
        )


def source_revision(root: pathlib.Path) -> tuple[str, str]:
    head = run(["git", "-C", str(root), "rev-parse", "HEAD"]).decode().strip()
    tree = run(
        ["git", "-C", str(root), "rev-parse", "HEAD^{tree}"]
    ).decode().strip()
    return head, tree


def require_clean_checkout(root: pathlib.Path, label: str) -> None:
    status = run(
        [
            "git",
            "-C",
            str(root),
            "status",
            "--porcelain",
            "--untracked-files=all",
        ]
    ).decode().splitlines()
    if not status:
        return
    require(
        label == "application"
        and os.environ.get("NVPN_LOCAL_FIPS_PATCH_PRECONFIGURED") == "1"
        and status == [" M Cargo.lock"],
        f"{label} checkout is dirty",
    )
    for path, variable in (
        ("Cargo.toml", "NVPN_LOCAL_FIPS_SESSION_CARGO_TOML_SHA256"),
        ("Cargo.lock", "NVPN_LOCAL_FIPS_SESSION_CARGO_LOCK_SHA256"),
    ):
        expected = os.environ.get(variable, "")
        require(
            re.fullmatch(r"[0-9a-f]{64}", expected) is not None
            and sha256_file(root / path) == expected,
            f"application {path} changed outside the exact FIPS session",
        )


def validate_source_and_fips(args: argparse.Namespace) -> None:
    require(
        args.rust_profile == "release",
        "frozen iOS archive requires the Release Rust profile",
    )
    source_root = pathlib.Path(args.source_root)
    fips_root = pathlib.Path(args.fips_root)
    app_head, app_tree = source_revision(source_root)
    fips_head, fips_tree = source_revision(fips_root)
    require(app_head == args.app_head, "application HEAD changed")
    require(app_tree == args.app_tree, "application tree changed")
    require(fips_head == args.fips_head, "FIPS HEAD changed")
    require(fips_tree == args.fips_tree, "FIPS tree changed")
    require_clean_checkout(source_root, "application")
    require_clean_checkout(fips_root, "FIPS")
    validate_fips_metadata(
        pathlib.Path(args.fips_metadata),
        path_sha256(fips_root),
        args.fips_head,
        args.fips_tree,
        args.fips_version,
    )


def archive_app(archive: pathlib.Path) -> pathlib.Path:
    return archive / "Products" / "Applications" / APP_NAME


def freeze_archive(args: argparse.Namespace) -> None:
    archive = pathlib.Path(args.archive).resolve()
    receipt_path = pathlib.Path(args.receipt)
    require(archive.is_dir(), f"iOS archive is missing: {archive}")
    validate_source_and_fips(args)
    app = archive_app(archive)
    identity = bundle_identity(app)
    validate_identity(
        identity,
        app_head=args.app_head,
        version=args.version,
        build=args.build,
        app_bundle_id=args.app_bundle_id,
        tunnel_bundle_id=args.tunnel_bundle_id,
    )
    signing = signed_bundle_audit(
        app,
        distribution="app-store-connect",
        team_id=args.team_id,
        signer_sha=args.signer_sha,
        app_bundle_id=args.app_bundle_id,
        tunnel_bundle_id=args.tunnel_bundle_id,
        app_group_id=args.app_group_id,
        device_udid="",
    )
    fips_metadata = pathlib.Path(args.fips_metadata).resolve()
    receipt = {
        "receiptSchema": RECEIPT_SCHEMA,
        "artifactType": "iOS frozen App Store xcarchive",
        "archiveAppBundleTreeSha256": tree_sha256(app),
        "archivePathSha256": path_sha256(archive),
        "archiveTreeSha256": tree_sha256(archive),
        "appGitSha": args.app_head,
        "appGitTree": args.app_tree,
        "fipsCargoMetadataReceiptPathSha256": path_sha256(fips_metadata),
        "fipsCargoMetadataReceiptSha256": sha256_file(fips_metadata),
        "fipsCheckoutPathSha256": path_sha256(pathlib.Path(args.fips_root)),
        "fipsCoreVersion": args.fips_version,
        "fipsGitSha": args.fips_head,
        "fipsGitTree": args.fips_tree,
        "identity": identity,
        "rustBuildProfile": args.rust_profile,
        "signing": signing,
    }
    atomic_json(receipt_path, receipt)


def validate_archive_receipt(
    args: argparse.Namespace,
) -> tuple[dict[str, Any], pathlib.Path, dict[str, Any]]:
    archive = pathlib.Path(args.archive).resolve()
    receipt_path = pathlib.Path(args.archive_receipt)
    receipt = load_json(receipt_path)
    require(
        receipt.get("receiptSchema") == RECEIPT_SCHEMA
        and receipt.get("artifactType") == "iOS frozen App Store xcarchive",
        "frozen iOS archive receipt has the wrong schema or type",
    )
    validate_source_and_fips(args)
    app = archive_app(archive)
    fips_metadata = pathlib.Path(args.fips_metadata).resolve()
    expected_receipt = {
        "appGitSha": args.app_head,
        "appGitTree": args.app_tree,
        "archiveAppBundleTreeSha256": tree_sha256(app),
        "archivePathSha256": path_sha256(archive),
        "archiveTreeSha256": tree_sha256(archive),
        "fipsCargoMetadataReceiptPathSha256": path_sha256(fips_metadata),
        "fipsCargoMetadataReceiptSha256": sha256_file(fips_metadata),
        "fipsCheckoutPathSha256": path_sha256(
            pathlib.Path(args.fips_root)
        ),
        "fipsCoreVersion": args.fips_version,
        "fipsGitSha": args.fips_head,
        "fipsGitTree": args.fips_tree,
        "rustBuildProfile": args.rust_profile,
    }
    for name, expected in expected_receipt.items():
        require(
            receipt.get(name) == expected,
            f"frozen iOS archive receipt {name} changed",
        )
    require(
        receipt.get("rustBuildProfile") == "release",
        "frozen iOS archive did not use the Release Rust profile",
    )
    identity = bundle_identity(app)
    require(identity == receipt.get("identity"), "frozen archive code identity changed")
    validate_identity(
        identity,
        app_head=args.app_head,
        version=args.version,
        build=args.build,
        app_bundle_id=args.app_bundle_id,
        tunnel_bundle_id=args.tunnel_bundle_id,
    )
    signing = signed_bundle_audit(
        app,
        distribution="app-store-connect",
        team_id=args.team_id,
        signer_sha=args.signer_sha,
        app_bundle_id=args.app_bundle_id,
        tunnel_bundle_id=args.tunnel_bundle_id,
        app_group_id=args.app_group_id,
        device_udid="",
    )
    require(signing == receipt.get("signing"), "frozen archive signing changed")
    return receipt, app, identity


def validate_export(args: argparse.Namespace) -> None:
    receipt, archive_app, archive_identity = validate_archive_receipt(args)
    app = pathlib.Path(args.app).resolve()
    ipa = pathlib.Path(args.ipa).resolve()
    require(ipa.is_file(), f"exported iOS IPA is missing: {ipa}")
    require(
        export_equivalence_identity(app)
        == export_equivalence_identity(archive_app),
        "exported iOS app is not code/content-identical to the frozen archive",
    )
    signing = signed_bundle_audit(
        app,
        distribution=args.distribution,
        team_id=args.team_id,
        signer_sha=args.signer_sha,
        app_bundle_id=args.app_bundle_id,
        tunnel_bundle_id=args.tunnel_bundle_id,
        app_group_id=args.app_group_id,
        device_udid=args.device_udid,
    )
    export_receipt = {
        "receiptSchema": RECEIPT_SCHEMA,
        "artifactType": "iOS export from frozen xcarchive",
        "appBundleTreeSha256": tree_sha256(app),
        "appGitSha": receipt["appGitSha"],
        "appGitTree": receipt["appGitTree"],
        "archiveReceiptSha256": sha256_file(
            pathlib.Path(args.archive_receipt)
        ),
        "archiveTreeSha256": receipt["archiveTreeSha256"],
        "distribution": args.distribution,
        "fipsCoreVersion": receipt["fipsCoreVersion"],
        "fipsGitSha": receipt["fipsGitSha"],
        "fipsGitTree": receipt["fipsGitTree"],
        "identity": archive_identity,
        "ipaPathSha256": path_sha256(ipa),
        "ipaSha256": sha256_file(ipa),
        "rustBuildProfile": receipt["rustBuildProfile"],
        "signing": signing,
    }
    atomic_json(pathlib.Path(args.output), export_receipt)


def add_revision_arguments(parser: argparse.ArgumentParser) -> None:
    for name in (
        "source_root",
        "fips_root",
        "fips_metadata",
        "app_head",
        "app_tree",
        "fips_head",
        "fips_tree",
        "fips_version",
        "rust_profile",
        "version",
        "build",
        "app_bundle_id",
        "tunnel_bundle_id",
        "app_group_id",
        "team_id",
        "signer_sha",
    ):
        parser.add_argument(f"--{name.replace('_', '-')}", required=True)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    subparsers = result.add_subparsers(dest="command", required=True)

    identity = subparsers.add_parser("identity")
    identity.add_argument("--app", required=True)

    rewrite = subparsers.add_parser("rewrite-xctestrun")
    rewrite.add_argument("--source", required=True)
    rewrite.add_argument("--output", required=True)
    rewrite.add_argument("--products-root", required=True)
    rewrite.add_argument("--target-app", required=True)
    rewrite.add_argument("--use-destination-artifacts", action="store_true")
    rewrite.add_argument("--environment", action="append", default=[])
    rewrite.add_argument("--environment-stdin0", action="store_true")
    freeze = subparsers.add_parser("freeze")
    freeze.add_argument("--archive", required=True)
    freeze.add_argument("--receipt", required=True)
    add_revision_arguments(freeze)

    validate_archive = subparsers.add_parser("validate-archive")
    validate_archive.add_argument("--archive", required=True)
    validate_archive.add_argument("--archive-receipt", required=True)
    add_revision_arguments(validate_archive)

    export = subparsers.add_parser("validate-export")
    export.add_argument("--archive", required=True)
    export.add_argument("--archive-receipt", required=True)
    export.add_argument("--app", required=True)
    export.add_argument("--ipa", required=True)
    export.add_argument("--output", required=True)
    export.add_argument(
        "--distribution",
        choices=("release-testing", "app-store-connect"),
        required=True,
    )
    export.add_argument("--device-udid", default="")
    add_revision_arguments(export)

    seal = subparsers.add_parser("seal-gate")
    seal.add_argument("--archive-receipt", required=True)
    seal.add_argument("--adhoc-receipt", required=True)
    seal.add_argument("--mobile-receipt", required=True)
    seal.add_argument("--mobile-join-ios-variant-receipt", required=True)
    seal.add_argument("--mobile-join-receipt", required=True)
    seal.add_argument("--mobile-wg-receipt", required=True)
    seal.add_argument("--mobile-underlay-receipt", required=True)
    seal.add_argument("--desktop-mobile-join-receipt", required=True)
    seal.add_argument("--sealed-mobile-receipt", required=True)
    seal.add_argument("--output", required=True)
    seal.add_argument("--required-gate", action="append", default=[])

    validate_seal = subparsers.add_parser("validate-gate-seal")
    validate_seal.add_argument("--archive-receipt", required=True)
    validate_seal.add_argument("--adhoc-receipt", required=True)
    validate_seal.add_argument("--sealed-mobile-receipt", required=True)
    validate_seal.add_argument(
        "--mobile-join-ios-variant-receipt", required=True
    )
    validate_seal.add_argument("--mobile-join-receipt", required=True)
    validate_seal.add_argument("--mobile-wg-receipt", required=True)
    validate_seal.add_argument("--mobile-underlay-receipt", required=True)
    validate_seal.add_argument("--desktop-mobile-join-receipt", required=True)
    validate_seal.add_argument("--gate-seal", required=True)
    validate_seal.add_argument("--required-gate", action="append", default=[])
    return result


def main() -> int:
    args = parser().parse_args()
    try:
        if args.command == "identity":
            print(
                json.dumps(
                    bundle_identity(pathlib.Path(args.app)),
                    indent=2,
                    sort_keys=True,
                )
            )
        elif args.command == "rewrite-xctestrun":
            rewrite_xctestrun(args)
        elif args.command == "freeze":
            freeze_archive(args)
        elif args.command == "validate-archive":
            validate_archive_receipt(args)
        elif args.command == "validate-export":
            validate_export(args)
        elif args.command == "seal-gate":
            seal_gate(args)
        elif args.command == "validate-gate-seal":
            validate_gate_seal(args)
        else:
            raise ValueError(f"unsupported command: {args.command}")
    except (
        OSError,
        ValueError,
        json.JSONDecodeError,
        plistlib.InvalidFileException,
    ) as error:
        print(f"frozen iOS archive rejected: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
