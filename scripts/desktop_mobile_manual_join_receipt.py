#!/usr/bin/env python3
"""Validate and bind real desktop↔Pixel manual-join Release evidence.

Desktop and Android artifacts are independently versioned components.  Their
source identities may legitimately differ when an unchanged sealed artifact is
reused, so this verifier binds each component to its own source, FIPS linkage,
artifact receipt, and payload digest instead of inventing a shared repository
identity.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import subprocess
import tempfile
from typing import Any, NoReturn


GIT_SHA = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[+-][0-9A-Za-z.-]+)?$")
PLATFORMS = ("windows", "linux")
ROLES = ("desktopAdminPixelJoiner", "pixelAdminDesktopJoiner")
ROLE_FLAGS = (
    "desktopAccepted",
    "pixelAccepted",
    "desktopRelaunchAccepted",
    "pixelRelaunchAccepted",
)


def fail(message: str) -> NoReturn:
    raise ValueError(message)


def load_json(path: pathlib.Path, label: str) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink():
        fail(f"{label} is not a regular non-symlink file")
    try:
        value = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError) as error:
        fail(f"could not parse {label}: {error}")
    if not isinstance(value, dict):
        fail(f"{label} root is not an object")
    return value


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def require_regular_file(path: pathlib.Path, label: str) -> None:
    if not path.is_file() or path.is_symlink():
        fail(f"{label} is not a regular non-symlink file")


def require_exact(value: dict[str, Any], key: str, expected: Any, label: str) -> None:
    if value.get(key) != expected:
        fail(f"{label} requires {key}={expected!r}")


def require_git_sha(value: str, label: str) -> None:
    if not GIT_SHA.fullmatch(value):
        fail(f"{label} is not an exact Git SHA")


def require_sha256(value: Any, label: str) -> str:
    if not isinstance(value, str):
        fail(f"{label} is not a SHA-256 string")
    normalized = value.lower()
    if not SHA256.fullmatch(normalized):
        fail(f"{label} is not an exact SHA-256")
    return normalized


def require_artifact_entry(
    artifacts: dict[str, Any], name: str, label: str
) -> dict[str, Any]:
    entry = artifacts.get(name)
    if not isinstance(entry, dict):
        fail(f"{label} lacks the {name} artifact")
    require_sha256(entry.get("sha256"), f"{label} {name} hash")
    size = entry.get("size")
    if not isinstance(size, int) or isinstance(size, bool) or size <= 0:
        fail(f"{label} {name} size is not positive")
    filename = entry.get("file")
    if not isinstance(filename, str) or not filename.strip():
        fail(f"{label} {name} filename is empty")
    return entry


def validate_desktop_receipt(
    receipt: dict[str, Any],
    platform: str,
    app_sha: str,
    app_tree: str,
    fips_sha: str,
    fips_tree: str,
    fips_version: str,
    registry_proof: dict[str, Any] | None = None,
) -> dict[str, Any]:
    label = f"{platform} desktop artifact receipt"
    require_exact(receipt, "schema", 2 if platform == "linux" else 1, label)
    require_exact(receipt, "appGitSha", app_sha, label)
    require_exact(receipt, "appGitTree", app_tree, label)
    require_exact(receipt, "fipsGitSha", fips_sha, label)
    require_exact(receipt, "fipsGitTree", fips_tree, label)
    require_exact(receipt, "fipsVersion", fips_version, label)
    version = receipt.get("appVersion")
    if not isinstance(version, str) or not VERSION.fullmatch(version):
        fail(f"{label} has no valid appVersion")
    artifacts = receipt.get("artifacts")
    if not isinstance(artifacts, dict):
        fail(f"{label} has no artifact map")
    app = require_artifact_entry(artifacts, "app", label)
    cli = require_artifact_entry(artifacts, "cli", label)

    if platform == "windows":
        require_exact(receipt, "platform", "windows", label)
        require_exact(receipt, "configuration", "Release", label)
        require_exact(receipt, "builtOnWindowsVm", True, label)
        app_core = require_artifact_entry(artifacts, "appCore", label)
        if cli.get("shortVersion") != f"nvpn {version}":
            fail(f"{label} CLI version differs from appVersion")
        verbose = cli.get("verboseVersion")
        if registry_proof is None:
            if not isinstance(verbose, str) or f"(rev {fips_sha[:10]})" not in verbose:
                fail(f"{label} CLI does not bind the exact FIPS revision")
        else:
            require_exact(registry_proof, "cliSha256", cli["sha256"], label)
            require_exact(registry_proof, "cliSize", cli["size"], label)
            require_exact(registry_proof, "expectedFipsVersion", fips_version, label)
            lines = [line.strip() for line in verbose.splitlines()
                     if line.strip().startswith("fips_core_version:")]
            if lines != [registry_proof.get("runtimeFipsVersion")]:
                fail(f"{label} runtime differs from verified registry provenance")
    else:
        mode = receipt.get("builderMode")
        if mode == "local-docker":
            require_exact(receipt, "builtOnHostMac", True, label)
            require_exact(receipt, "builtOnRemoteVm", False, label)
            require_exact(receipt, "builderHostOs", "Darwin", label)
            if receipt.get("builderHostArchitecture") not in {"arm64", "x86_64"}:
                fail(f"{label} has invalid local Docker host architecture")
        elif mode == "remote-native":
            require_exact(receipt, "builtOnHostMac", False, label)
            require_exact(receipt, "builtOnRemoteVm", True, label)
            require_exact(receipt, "builderHostOs", "Linux", label)
            require_exact(receipt, "builderHostArchitecture", "x86_64", label)
        else:
            fail(f"{label} has unsupported builderMode")
        require_sha256(receipt.get("dockerfileSha256"), f"{label} Dockerfile hash")
        require_sha256(
            receipt.get("containerPayloadSha256"),
            f"{label} container payload hash",
        )
        image_id = receipt.get("containerImageId")
        if not isinstance(image_id, str) or not re.fullmatch(
            r"sha256:[0-9a-f]{64}", image_id
        ):
            fail(f"{label} has invalid container image identity")
        require_exact(receipt, "dockerPlatform", "linux/amd64", label)
        require_exact(receipt, "target", "x86_64-unknown-linux-gnu", label)
        app_core = None
        if receipt.get("cliShortVersion") != f"nvpn {version}":
            fail(f"{label} CLI version differs from appVersion")
        verbose = receipt.get("cliVerboseVersion")
        if not isinstance(verbose, str) or f"(rev {fips_sha[:10]})" not in verbose:
            fail(f"{label} CLI does not bind the exact FIPS revision")

    result: dict[str, Any] = {
        "artifactReceiptSha256": "",
        "artifactReceiptSize": 0,
        "appGitSha": app_sha,
        "appGitTree": app_tree,
        "fipsGitSha": fips_sha,
        "fipsGitTree": fips_tree,
        "fipsVersion": fips_version,
        "appSha256": app["sha256"],
        "appSize": app["size"],
        "cliSha256": cli["sha256"],
        "cliSize": cli["size"],
        "appVersion": version,
    }
    if app_core is not None:
        result["appCoreSha256"] = app_core["sha256"]
        result["appCoreSize"] = app_core["size"]
    return result


def validate_android_artifact_receipt(
    receipt: dict[str, Any],
    apk: pathlib.Path,
    app_sha: str,
    app_tree: str,
    fips_sha: str,
    fips_tree: str,
    fips_version: str,
) -> dict[str, Any]:
    label = "Android Release artifact receipt"
    require_regular_file(apk, "Android APK")
    apk_hash = sha256_file(apk)
    require_exact(receipt, "receiptSchema", 2, label)
    require_exact(receipt, "artifactType", "Android Release APK", label)
    require_exact(receipt, "apkDerivedFromAab", True, label)
    require_sha256(receipt.get("aabSha256"), "Android sealed AAB hash")
    require_sha256(
        receipt.get("bundleReceiptSha256"),
        "Android AAB derivation receipt hash",
    )
    require_sha256(
        receipt.get("bundletoolSha256"), "Android bundletool hash"
    )
    if not isinstance(receipt.get("bundletoolVersion"), str):
        fail("Android bundletool version is missing")
    require_exact(receipt, "apkSha256", apk_hash, label)
    require_exact(receipt, "installedApkSha256", apk_hash, label)
    require_exact(receipt, "appGitSha", app_sha, label)
    require_exact(receipt, "appGitTree", app_tree, label)
    require_exact(receipt, "fipsGitSha", fips_sha, label)
    require_exact(receipt, "fipsGitTree", fips_tree, label)
    require_exact(receipt, "fipsCoreVersion", fips_version, label)
    require_exact(receipt, "package", "fi.siriusbusiness.nvpn", label)
    require_exact(receipt, "replacementInstall", True, label)
    require_exact(receipt, "companySigningVerified", True, label)
    require_exact(receipt, "debuggable", False, label)
    signer = require_sha256(
        receipt.get("signerCertificateSha256"),
        "Android Release signer certificate",
    )
    metadata_hash = require_sha256(
        receipt.get("fipsCargoMetadataReceiptSha256"),
        "Android FIPS metadata receipt hash",
    )
    return {
        "apkSha256": apk_hash,
        "apkSize": apk.stat().st_size,
        "signerCertificateSha256": signer,
        "package": receipt["package"],
        "fipsMetadataReceiptSha256": metadata_hash,
    }


def validate_android_install_receipt(
    receipt: dict[str, Any],
    *,
    apk_hash: str,
    signer: str,
    app_sha: str,
    app_tree: str,
    fips_sha: str,
    fips_tree: str,
    allow_verified_no_install: bool = False,
) -> None:
    label = "Android Release install receipt"
    require_exact(receipt, "artifact", "Android Release APK", label)
    require_exact(receipt, "apkSha256", apk_hash, label)
    require_exact(receipt, "installedApkSha256", apk_hash, label)
    require_exact(receipt, "signerCertificateSha256", signer, label)
    require_exact(receipt, "appGitSha", app_sha, label)
    require_exact(receipt, "appGitTree", app_tree, label)
    require_exact(receipt, "fipsGitSha", fips_sha, label)
    require_exact(receipt, "fipsGitTree", fips_tree, label)
    require_exact(receipt, "package", "fi.siriusbusiness.nvpn", label)
    if receipt.get("replacementInstall") is True:
        require_exact(receipt, "replacementInstallVerified", True, label)
    elif allow_verified_no_install:
        require_exact(receipt, "replacementInstall", False, label)
        require_exact(receipt, "replacementInstallVerified", False, label)
        require_exact(receipt, "installedArtifactVerified", True, label)
    else:
        require_exact(receipt, "replacementInstall", True, label)
    require_exact(receipt, "debuggable", False, label)
    require_exact(receipt, "canonicalPackageCount", 1, label)
    require_exact(receipt, "canonicalProcessCount", 1, label)


def validate_profile_isolation(
    evidence: dict[str, Any], platform: str, desktop: dict[str, Any] | None
) -> dict[str, Any]:
    label = f"{platform} desktop profile isolation"
    isolation = evidence.get("profileIsolation")
    if evidence.get("appLaunchArgumentsOrEnvironment") is False and "profileIsolation" not in evidence:
        return {"appLaunchArgumentsOrEnvironment": False}
    if platform != "windows" or evidence.get("appLaunchArgumentsOrEnvironment") is not True:
        fail(f"{label} only permits explicit Windows production profile isolation")
    expected_keys = {
        "schema", "kind", "environmentKeys", "appArguments", "guiDirectorySha256",
        "serviceDirectorySha256", "originalDirectorySha256", "originalBeforeSha256",
        "originalAfterSha256", "originalProfileUnchanged", "appSha256", "serviceCliSha256",
        "guiModes", "serviceInstallCount",
    }
    if not isinstance(isolation, dict) or set(isolation) != expected_keys or not desktop:
        fail(f"{label} lacks complete profile/artifact bindings")
    for key, expected in {
        "schema": 1, "kind": "production-data-directory",
        "environmentKeys": ["NVPN_APP_DATA_DIR"], "appArguments": [],
        "originalProfileUnchanged": True, "serviceInstallCount": 2,
        "guiModes": ["AdminAdd", "Bootstrap", "CreateAdmin", "ManualJoin", "Verify", "Verify"],
        "appSha256": desktop.get("appSha256"), "serviceCliSha256": desktop.get("cliSha256"),
    }.items():
        if type(isolation.get(key)) is not type(expected) or isolation.get(key) != expected:
            fail(f"{label} has invalid {key}")
    for key in expected_keys:
        if key.endswith("Sha256"):
            require_sha256(isolation[key], f"{label} {key}")
    if (isolation["guiDirectorySha256"] != isolation["serviceDirectorySha256"]
            or isolation["guiDirectorySha256"] == isolation["originalDirectorySha256"]
            or isolation["originalBeforeSha256"] != isolation["originalAfterSha256"]):
        fail(f"{label} changed the original profile or mismatched GUI/service directories")
    return {"appLaunchArgumentsOrEnvironment": True, "profileIsolation": isolation}


def validate_phase_evidence(
    evidence: dict[str, Any], platform: str, desktop: dict[str, Any] | None = None
) -> dict[str, Any]:
    label = f"{platform} desktop↔Pixel phase evidence"
    require_exact(evidence, "schema", 1, label)
    require_exact(evidence, "platform", platform, label)
    require_exact(evidence, "publicUiOnly", True, label)
    require_exact(evidence, "privateStateRead", False, label)
    require_exact(evidence, "fixtureInvoked", False, label)
    isolation = validate_profile_isolation(evidence, platform, desktop)
    require_exact(
        evidence,
        "acceptedSelectorSemantics",
        "participant-state-not-pending",
        label,
    )
    deadline = evidence.get("completionDeadlineSeconds")
    if (
        not isinstance(deadline, int)
        or isinstance(deadline, bool)
        or deadline <= 0
        or deadline > 15
    ):
        fail(f"{label} completion deadline exceeds 15 seconds")
    validated_roles: dict[str, Any] = {}
    for role_name in ROLES:
        role = evidence.get(role_name)
        if not isinstance(role, dict):
            fail(f"{label} lacks role {role_name}")
        for flag in ROLE_FLAGS:
            require_exact(role, flag, True, f"{label} {role_name}")
        elapsed = role.get("deliveryMilliseconds")
        if (
            not isinstance(elapsed, int)
            or isinstance(elapsed, bool)
            or elapsed < 0
            or elapsed > deadline * 1000
        ):
            fail(f"{label} {role_name} delivery exceeded the deadline")
        validated_roles[role_name] = {
            **{flag: True for flag in ROLE_FLAGS},
            "deliveryMilliseconds": elapsed,
        }
    return {
        "completionDeadlineSeconds": deadline,
        **isolation,
        **validated_roles,
    }


def write_json_atomically(path: pathlib.Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = pathlib.Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def validate_component_arguments(args: argparse.Namespace) -> None:
    for value, label in (
        (args.expected_desktop_app_sha, "expected desktop app SHA"),
        (args.expected_desktop_app_tree, "expected desktop app tree"),
        (args.expected_desktop_fips_sha, "expected desktop FIPS SHA"),
        (args.expected_desktop_fips_tree, "expected desktop FIPS tree"),
        (args.expected_android_app_sha, "expected Android app SHA"),
        (args.expected_android_app_tree, "expected Android app tree"),
        (args.expected_android_fips_sha, "expected Android FIPS SHA"),
        (args.expected_android_fips_tree, "expected Android FIPS tree"),
    ):
        require_git_sha(value, label)
    for value, label in (
        (args.expected_desktop_fips_version, "expected desktop FIPS version"),
        (args.expected_android_fips_version, "expected Android FIPS version"),
    ):
        if not VERSION.fullmatch(value):
            fail(f"{label} is invalid")


def validate_windows_registry_binding(
    args: argparse.Namespace, desktop: dict[str, Any]
) -> dict[str, Any] | None:
    paths = [args.windows_source_receipt, args.windows_installer_receipt,
             args.windows_fips_repo]
    if not any(paths):
        return None
    if args.platform != "windows" or not all(paths):
        fail("Windows registry provenance requires source, installer and FIPS inputs")
    load_json(args.windows_source_receipt, "Windows source receipt")
    installer = load_json(args.windows_installer_receipt, "Windows installer receipt")
    artifacts = desktop.get("artifacts", {})
    for name in ("app", "appCore", "cli", "wintun"):
        actual = require_artifact_entry(artifacts, name, "Windows desktop receipt")
        expected = installer.get("payloads", {}).get(name, {})
        for field in ("sha256", "size"):
            require_exact(actual, field, expected.get(field), f"Windows {name} artifact")
    cli = artifacts["cli"]
    verbose = cli.get("verboseVersion")
    if not isinstance(verbose, str):
        fail("Windows CLI runtime version is missing")
    # Recompute the canonical proof from actual locked registry packages and
    # their .cargo_vcs_info.json; never trust an unvalidated proof JSON alone.
    with tempfile.TemporaryDirectory(prefix="nvpn-windows-runtime-") as work:
        runtime = pathlib.Path(work) / "version.txt"
        runtime.write_text(verbose, encoding="utf-8")
        command = [
            "node", str(pathlib.Path(__file__).with_name("release-source-verification.mjs")),
            "windows-runtime-provenance", str(args.windows_source_receipt),
            str(args.windows_installer_receipt), args.expected_desktop_app_sha,
            args.expected_desktop_app_tree, str(args.windows_fips_repo),
            args.expected_desktop_fips_sha, args.expected_desktop_fips_tree,
            args.expected_desktop_fips_version, str(runtime), cli["sha256"], str(cli["size"]),
        ]
        result = subprocess.run(command, capture_output=True, text=True, timeout=90)
    if result.returncode:
        fail("Windows registry runtime provenance rejected: " + result.stderr.strip())
    proof = json.loads(result.stdout)
    return proof


def build_receipt(args: argparse.Namespace) -> dict[str, Any]:
    validate_component_arguments(args)

    desktop_source = load_json(args.desktop_receipt, "desktop artifact receipt")
    android_artifact_source = load_json(
        args.android_artifact_receipt, "Android artifact receipt"
    )
    android_source = load_json(
        args.android_install_receipt, "Android install receipt"
    )
    phase_source = load_json(args.phase_evidence, "phase evidence")
    registry_proof = validate_windows_registry_binding(args, desktop_source)
    desktop = validate_desktop_receipt(
        desktop_source,
        args.platform,
        args.expected_desktop_app_sha,
        args.expected_desktop_app_tree,
        args.expected_desktop_fips_sha,
        args.expected_desktop_fips_tree,
        args.expected_desktop_fips_version,
        registry_proof,
    )
    if registry_proof is not None:
        desktop["registryProvenance"] = registry_proof
        desktop["registrySourceReceiptSha256"] = sha256_file(args.windows_source_receipt)
        desktop["installerReceiptSha256"] = sha256_file(args.windows_installer_receipt)
    desktop["artifactReceiptSha256"] = sha256_file(args.desktop_receipt)
    desktop["artifactReceiptSize"] = args.desktop_receipt.stat().st_size
    android = validate_android_artifact_receipt(
        android_artifact_source,
        args.android_apk,
        args.expected_android_app_sha,
        args.expected_android_app_tree,
        args.expected_android_fips_sha,
        args.expected_android_fips_tree,
        args.expected_android_fips_version,
    )
    validate_android_install_receipt(
        android_source,
        apk_hash=android["apkSha256"],
        signer=android["signerCertificateSha256"],
        app_sha=args.expected_android_app_sha,
        app_tree=args.expected_android_app_tree,
        fips_sha=args.expected_android_fips_sha,
        fips_tree=args.expected_android_fips_tree,
        allow_verified_no_install=args.allow_verified_no_install,
    )
    require_regular_file(
        args.android_fips_metadata_receipt,
        "Android FIPS metadata receipt",
    )
    require_exact(
        android,
        "fipsMetadataReceiptSha256",
        sha256_file(args.android_fips_metadata_receipt),
        "Android Release artifact receipt",
    )
    android.update(
        {
            "artifactReceiptSha256": sha256_file(
                args.android_artifact_receipt
            ),
            "artifactReceiptSize": (
                args.android_artifact_receipt.stat().st_size
            ),
            "installReceiptSha256": sha256_file(args.android_install_receipt),
            "installReceiptSize": args.android_install_receipt.stat().st_size,
            "appGitSha": args.expected_android_app_sha,
            "appGitTree": args.expected_android_app_tree,
            "fipsGitSha": args.expected_android_fips_sha,
            "fipsGitTree": args.expected_android_fips_tree,
            "fipsVersion": args.expected_android_fips_version,
        }
    )
    phases = validate_phase_evidence(phase_source, args.platform, desktop)
    return {
        "schema": 2,
        "platform": args.platform,
        "artifact": {
            "desktop": desktop,
            "android": android,
        },
        "publicUiOnly": True,
        "privateStateRead": False,
        "fixtureInvoked": False,
        "acceptedSelectorSemantics": "participant-state-not-pending",
        "desktopRelaunchDurability": True,
        "pixelRelaunchDurability": True,
        **phases,
    }


def create_receipt(args: argparse.Namespace) -> None:
    output = build_receipt(args)
    write_json_atomically(args.output, output)


def validate_receipt(args: argparse.Namespace) -> None:
    receipt = load_json(args.receipt, "desktop↔Pixel receipt")
    expected = build_receipt(args)
    if receipt != expected:
        fail("desktop↔Pixel receipt differs from its bound artifact evidence")


def validate_android_only(args: argparse.Namespace) -> None:
    for value, label in (
        (args.expected_android_app_sha, "expected Android app SHA"),
        (args.expected_android_app_tree, "expected Android app tree"),
        (args.expected_android_fips_sha, "expected Android FIPS SHA"),
        (args.expected_android_fips_tree, "expected Android FIPS tree"),
    ):
        require_git_sha(value, label)
    if not VERSION.fullmatch(args.expected_android_fips_version):
        fail("expected Android FIPS version is invalid")
    artifact_receipt = load_json(
        args.android_artifact_receipt, "Android artifact receipt"
    )
    install_receipt = load_json(args.receipt, "Android install receipt")
    validated = validate_android_artifact_receipt(
        artifact_receipt,
        args.apk,
        args.expected_android_app_sha,
        args.expected_android_app_tree,
        args.expected_android_fips_sha,
        args.expected_android_fips_tree,
        args.expected_android_fips_version,
    )
    validate_android_install_receipt(
        install_receipt,
        apk_hash=validated["apkSha256"],
        signer=validated["signerCertificateSha256"],
        app_sha=args.expected_android_app_sha,
        app_tree=args.expected_android_app_tree,
        fips_sha=args.expected_android_fips_sha,
        fips_tree=args.expected_android_fips_tree,
        allow_verified_no_install=args.allow_verified_no_install,
    )
    require_regular_file(
        args.android_fips_metadata_receipt,
        "Android FIPS metadata receipt",
    )
    require_exact(
        validated,
        "fipsMetadataReceiptSha256",
        sha256_file(args.android_fips_metadata_receipt),
        "Android Release artifact receipt",
    )
    print(validated["apkSha256"])


def add_component_binding_arguments(command: argparse.ArgumentParser) -> None:
    command.add_argument("--desktop-receipt", type=pathlib.Path, required=True)
    command.add_argument("--windows-source-receipt", type=pathlib.Path)
    command.add_argument("--windows-installer-receipt", type=pathlib.Path)
    command.add_argument("--windows-fips-repo", type=pathlib.Path)
    command.add_argument(
        "--android-artifact-receipt", type=pathlib.Path, required=True
    )
    command.add_argument(
        "--android-install-receipt", type=pathlib.Path, required=True
    )
    command.add_argument(
        "--android-fips-metadata-receipt", type=pathlib.Path, required=True
    )
    command.add_argument("--android-apk", type=pathlib.Path, required=True)
    command.add_argument("--phase-evidence", type=pathlib.Path, required=True)
    command.add_argument("--allow-verified-no-install", action="store_true")
    for component in ("desktop", "android"):
        command.add_argument(f"--expected-{component}-app-sha", required=True)
        command.add_argument(f"--expected-{component}-app-tree", required=True)
        command.add_argument(f"--expected-{component}-fips-sha", required=True)
        command.add_argument(f"--expected-{component}-fips-tree", required=True)
        command.add_argument(f"--expected-{component}-fips-version", required=True)


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser()
    subcommands = root.add_subparsers(dest="command", required=True)
    create = subcommands.add_parser("create")
    create.add_argument("--platform", choices=PLATFORMS, required=True)
    add_component_binding_arguments(create)
    create.add_argument("--output", type=pathlib.Path, required=True)
    create.set_defaults(function=create_receipt)

    validate = subcommands.add_parser("validate")
    validate.add_argument("--platform", choices=PLATFORMS, required=True)
    validate.add_argument("--receipt", type=pathlib.Path, required=True)
    add_component_binding_arguments(validate)
    validate.set_defaults(function=validate_receipt)

    android = subcommands.add_parser("validate-android")
    android.add_argument("--receipt", type=pathlib.Path, required=True)
    android.add_argument(
        "--android-artifact-receipt", type=pathlib.Path, required=True
    )
    android.add_argument(
        "--android-fips-metadata-receipt", type=pathlib.Path, required=True
    )
    android.add_argument("--apk", type=pathlib.Path, required=True)
    android.add_argument("--expected-android-app-sha", required=True)
    android.add_argument("--expected-android-app-tree", required=True)
    android.add_argument("--expected-android-fips-sha", required=True)
    android.add_argument("--expected-android-fips-tree", required=True)
    android.add_argument("--expected-android-fips-version", required=True)
    android.add_argument("--allow-verified-no-install", action="store_true")
    android.set_defaults(function=validate_android_only)
    return root


def main() -> None:
    args = parser().parse_args()
    try:
        args.function(args)
    except (OSError, ValueError) as error:
        raise SystemExit(
            f"desktop/mobile manual-join receipt rejected: {error}"
        ) from error


if __name__ == "__main__":
    main()
