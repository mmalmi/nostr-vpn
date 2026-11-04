#!/usr/bin/env python3
"""Create and independently verify the imported macOS Release join artifact."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import ssl
import subprocess
import sys
import tempfile
from typing import Any

from mobile_release_artifact_receipt import (
    load_json,
    require_equal,
    sha256_file,
    tree_sha256,
)
from macos_hosted_admission import (
    receipt_fields, validate_admission, validate_receipt_admission, validate_receipt_binding,
)


def run(command: list[str], *, cwd: pathlib.Path | None = None) -> bytes:
    completed = subprocess.run(
        command,
        cwd=cwd,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return completed.stdout


def git_text(root: pathlib.Path, *arguments: str) -> str:
    return run(["git", "-C", str(root), *arguments]).decode().strip()


def git_snapshot(root: pathlib.Path) -> dict[str, str]:
    status = git_text(root, "status", "--porcelain", "--untracked-files=all")
    if status:
        expected_manifest = os.environ.get(
            "NVPN_LOCAL_FIPS_SESSION_CARGO_TOML_SHA256", ""
        )
        expected_lock = os.environ.get(
            "NVPN_LOCAL_FIPS_SESSION_CARGO_LOCK_SHA256", ""
        )
        manifest = root / "Cargo.toml"
        lock = root / "Cargo.lock"
        session_matches = (
            status.splitlines() == ["M Cargo.lock"]
            and re.fullmatch(r"[0-9a-f]{64}", expected_manifest) is not None
            and re.fullmatch(r"[0-9a-f]{64}", expected_lock) is not None
            and manifest.is_file()
            and lock.is_file()
            and hashlib.sha256(manifest.read_bytes()).hexdigest()
            == expected_manifest
            and hashlib.sha256(lock.read_bytes()).hexdigest() == expected_lock
        )
        if not session_matches:
            raise ValueError(f"source checkout is dirty: {root}")
    index = run(["git", "-C", str(root), "ls-tree", "-r", "-z", "HEAD"])
    return {
        "head": git_text(root, "rev-parse", "HEAD"),
        "tree": git_text(root, "rev-parse", "HEAD^{tree}"),
        "manifest": hashlib.sha256(index).hexdigest(),
    }


def git_snapshot_at(root: pathlib.Path, head: str) -> dict[str, str]:
    if git_text(root, "rev-parse", "HEAD") == head:
        return git_snapshot(root)
    resolved = git_text(root, "rev-parse", f"{head}^{{commit}}")
    if resolved != head:
        raise ValueError(f"source commit is not exact: {head}")
    index = run(["git", "-C", str(root), "ls-tree", "-r", "-z", head])
    return {
        "head": head,
        "tree": git_text(root, "rev-parse", f"{head}^{{tree}}"),
        "manifest": hashlib.sha256(index).hexdigest(),
    }


def fips_version(root: pathlib.Path) -> str:
    manifest = root / "crates" / "fips-core" / "Cargo.toml"
    text = manifest.read_text(encoding="utf-8")
    package = re.search(
        r"(?ms)^\[package\]\s*$.*?^version\s*=\s*\"([^\"]+)\"",
        text,
    )
    if not package:
        raise ValueError("could not derive the exact FIPS package version")
    return package.group(1)


def normalized_hex(value: str, length: int, label: str) -> str:
    normalized = re.sub(r"[:\s]", "", value).lower()
    if not re.fullmatch(rf"[0-9a-f]{{{length}}}", normalized):
        raise ValueError(f"{label} must be exactly {length} hexadecimal digits")
    return normalized


def resolve_certificate(identity_sha1: str) -> str:
    expected = normalized_hex(identity_sha1, 40, "signing identity SHA-1")
    output = run(["security", "find-certificate", "-a", "-p"])
    blocks = re.findall(
        rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
        output,
        re.DOTALL,
    )
    matches = []
    for block in blocks:
        certificate = ssl.PEM_cert_to_DER_cert(block.decode("ascii"))
        if hashlib.sha1(certificate).hexdigest() == expected:
            matches.append(hashlib.sha256(certificate).hexdigest())
    if len(matches) != 1:
        raise ValueError(
            "configured signing identity must resolve to exactly one certificate"
        )
    return matches[0]


def codesign_value(details: str, label: str) -> str:
    prefix = f"{label}="
    for line in details.splitlines():
        if line.startswith(prefix):
            return line.removeprefix(prefix)
    raise ValueError(f"macOS signature has no {label}")


def inspect_signature(path: pathlib.Path, *, deep: bool = False) -> dict[str, str]:
    verify = ["codesign", "--verify"]
    if deep:
        verify.append("--deep")
    verify.extend(["--strict", str(path)])
    run(verify)
    completed = subprocess.run(
        ["codesign", "-dvvv", str(path)],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    details = completed.stdout + completed.stderr
    with tempfile.TemporaryDirectory(prefix="nvpn-macos-release-cert.") as directory:
        prefix = pathlib.Path(directory) / "certificate"
        run(
            [
                "codesign",
                "-d",
                f"--extract-certificates={prefix}",
                str(path),
            ]
        )
        certificate = pathlib.Path(f"{prefix}0")
        if not certificate.is_file():
            raise ValueError("macOS signature has no extractable leaf certificate")
        certificate_bytes = certificate.read_bytes()
    return {
        "authority": codesign_value(details, "Authority"),
        "cdhash": codesign_value(details, "CDHash").lower(),
        "certificateSha1": hashlib.sha1(certificate_bytes).hexdigest(),
        "certificateSha256": hashlib.sha256(certificate_bytes).hexdigest(),
        "team": codesign_value(details, "TeamIdentifier"),
    }


def verify_signature(
    signature: dict[str, str],
    *,
    expected_team: str,
    expected_identity: str,
    expected_signer: str,
    label: str,
) -> None:
    if signature["team"] != expected_team:
        raise ValueError(f"{label} has the wrong signing team")
    if signature["certificateSha1"] != expected_identity:
        raise ValueError(f"{label} has the wrong signing identity")
    if signature["certificateSha256"] != expected_signer:
        raise ValueError(f"{label} has the wrong signer certificate")
    if not signature["authority"].startswith("Developer ID Application: "):
        raise ValueError(f"{label} is not Developer ID signed")


def observed_receipt(args: argparse.Namespace) -> dict[str, Any]:
    package = pathlib.Path(args.package).resolve()
    app = pathlib.Path(args.app).resolve()
    archive = pathlib.Path(args.archive).resolve()
    fixture = pathlib.Path(args.manual_join_fixture).resolve()
    manual_driver = pathlib.Path(args.manual_join_driver).resolve()
    service_driver = pathlib.Path(args.service_toggle_driver).resolve()
    component_proof = pathlib.Path(args.component_proof).resolve()
    app_root = pathlib.Path(args.app_root).resolve()
    fips_root = pathlib.Path(args.fips_root).resolve()
    executable = app / "Contents" / "MacOS" / "Nostr VPN"
    cli = app / "Contents" / "Resources" / "nvpn"
    for path in (
        archive,
        executable,
        cli,
        fixture,
        manual_driver,
        service_driver,
        component_proof,
    ):
        if not path.is_file():
            raise ValueError(f"required macOS Release artifact is missing: {path}")
    if not package.is_dir():
        raise ValueError(f"macOS Release package is missing: {package}")
    for path in (app, fixture, manual_driver, service_driver, component_proof):
        try:
            path.relative_to(package)
        except ValueError as error:
            raise ValueError(
                f"macOS Release package does not contain {path}"
            ) from error
    app_source = git_snapshot_at(app_root, args.expected_app_head)
    fips_source = git_snapshot(fips_root)
    expected_identity = normalized_hex(
        args.expected_identity_sha1, 40, "signing identity SHA-1"
    )
    expected_signer = normalized_hex(
        args.expected_signer_sha256, 64, "signer certificate SHA-256"
    )
    signature = inspect_signature(app, deep=True)
    fixture_signature = inspect_signature(fixture)
    manual_driver_signature = inspect_signature(manual_driver)
    service_driver_signature = inspect_signature(service_driver)
    expected = {
        "appGitSha": args.expected_app_head,
        "appGitTree": args.expected_app_tree,
        "fipsGitSha": args.expected_fips_head,
        "fipsGitTree": args.expected_fips_tree,
        "fipsCoreVersion": args.expected_fips_version,
    }
    actual = {
        "appGitSha": app_source["head"],
        "appGitTree": app_source["tree"],
        "fipsGitSha": fips_source["head"],
        "fipsGitTree": fips_source["tree"],
        "fipsCoreVersion": fips_version(fips_root),
    }
    proof = load_json(component_proof)
    expected_proof = {
        "policy": "unchanged-platform-product-inputs-v1",
        "platform": "macos",
        "receipt_app_git_sha": args.expected_app_head,
        "receipt_app_git_tree": args.expected_app_tree,
        "candidate_app_git_sha": args.expected_harness_head,
        "candidate_app_git_tree": args.expected_harness_tree,
    }
    if any(proof.get(name) != value for name, value in expected_proof.items()):
        raise ValueError("macOS component-input proof has the wrong source identity")
    if not re.fullmatch(r"[0-9a-f]{64}", proof.get("changed_paths_sha256", "")):
        raise ValueError("macOS component-input proof has no changed-path digest")
    for name, value in expected.items():
        if actual[name] != value:
            raise ValueError(
                f"{name} mismatch: expected {value!r}, got {actual[name]!r}"
            )
    verify_signature(
        signature,
        expected_team=args.expected_team,
        expected_identity=expected_identity,
        expected_signer=expected_signer,
        label="macOS Release app",
    )
    for label, support_signature in (
        ("macOS manual-join fixture", fixture_signature),
        ("macOS manual-join AX driver", manual_driver_signature),
        ("macOS service-toggle AX driver", service_driver_signature),
    ):
        verify_signature(
            support_signature,
            expected_team=args.expected_team,
            expected_identity=expected_identity,
            expected_signer=expected_signer,
            label=label,
        )
    bundle_manifest = tree_sha256(app)
    package_manifest = tree_sha256(package)
    receipt = {
        "receiptSchema": 1,
        "artifactType": "macOS company Developer ID Release gate package",
        "archiveSha256": sha256_file(archive),
        "archiveSize": archive.stat().st_size,
        "packageTreeSha256": package_manifest,
        "appBundleName": app.name,
        "appBundleTreeSha256": bundle_manifest,
        "bundleManifestSha256": bundle_manifest,
        "appExecutableSha256": sha256_file(executable),
        "cliExecutableSha256": sha256_file(cli),
        "appCodeDirectoryHash": signature["cdhash"],
        "manualJoinFixtureSha256": sha256_file(fixture),
        "manualJoinFixtureCodeDirectoryHash": fixture_signature["cdhash"],
        "manualJoinDriverSha256": sha256_file(manual_driver),
        "manualJoinDriverCodeDirectoryHash": manual_driver_signature["cdhash"],
        "serviceToggleDriverSha256": sha256_file(service_driver),
        "serviceToggleDriverCodeDirectoryHash": service_driver_signature["cdhash"],
        "componentInputProof": proof,
        "componentInputProofSha256": sha256_file(component_proof),
        "appGitSha": app_source["head"],
        "appGitTree": app_source["tree"],
        "appSourceManifestSha256": app_source["manifest"],
        "fipsGitSha": fips_source["head"],
        "fipsGitTree": fips_source["tree"],
        "fipsSourceManifestSha256": fips_source["manifest"],
        "fipsCoreVersion": actual["fipsCoreVersion"],
        "signingTeam": signature["team"],
        "signingAuthority": signature["authority"],
        "signingIdentitySha1": signature["certificateSha1"],
        "signerCertificateSha256": signature["certificateSha256"],
        "companySigningVerified": True,
        "configuration": "Release",
        "builtOnHost": True,
        "builtOnTestVm": False,
        "appLaunchArgumentsOrEnvironment": False,
        "privateAppStateRead": False,
    }
    companion = pathlib.Path(getattr(args, "hosted_admission", None) or package / "hosted-admission.json")
    if companion.exists():
        from macos_hosted_support import support_evidence, support_receipt_fields
        admission = validate_admission(companion, app)
        receipt.update(receipt_fields(companion, admission))
        receipt["shareFilesExecutableSha256"] = admission["appIdentity"]["shareFilesExecutableSha256"]
        validate_receipt_binding(receipt, companion, admission)
        receipt.update(support_receipt_fields(support_evidence(package, admission["signing"])))
    elif any(package.glob("*/hosted-inputs.json")) or getattr(args, "hosted_admission", None):
        raise ValueError("hosted macOS package is missing its mandatory admission")
    return receipt


def create_receipt(args: argparse.Namespace) -> None:
    receipt = observed_receipt(args)
    pathlib.Path(args.receipt).write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def validate_receipt(args: argparse.Namespace) -> None:
    receipt_path = pathlib.Path(args.receipt)
    receipt = load_json(receipt_path)
    observed = observed_receipt(args)
    for name, value in observed.items():
        require_equal(receipt, name, value)
    verification = {
        "receiptSchema": 1,
        "remoteImportVerified": True,
        "artifactReceiptSha256": sha256_file(receipt_path),
        "archiveSha256": observed["archiveSha256"],
        "packageTreeSha256": observed["packageTreeSha256"],
        "bundleManifestSha256": observed["bundleManifestSha256"],
        "appExecutableSha256": observed["appExecutableSha256"],
        "cliExecutableSha256": observed["cliExecutableSha256"],
        "manualJoinFixtureSha256": observed["manualJoinFixtureSha256"],
        "manualJoinDriverSha256": observed["manualJoinDriverSha256"],
        "serviceToggleDriverSha256": observed["serviceToggleDriverSha256"],
        "componentInputProofSha256": observed["componentInputProofSha256"],
        "appGitSha": observed["appGitSha"],
        "appGitTree": observed["appGitTree"],
        "fipsGitSha": observed["fipsGitSha"],
        "fipsGitTree": observed["fipsGitTree"],
        "fipsSourceManifestSha256": observed["fipsSourceManifestSha256"],
        "signingTeam": observed["signingTeam"],
        "signingIdentitySha1": observed["signingIdentitySha1"],
        "signerCertificateSha256": observed["signerCertificateSha256"],
        "builtOnHost": observed["builtOnHost"],
        "builtOnTestVm": False,
    }
    if observed["receiptSchema"] == 2:
        verification.update(buildOrigin="github-actions", signedOnHost=True,
                            hostedAdmissionReceiptSha256=observed["hostedAdmissionReceiptSha256"])
    pathlib.Path(args.verification_output).write_text(
        json.dumps(verification, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def validate_published_app(args: argparse.Namespace) -> None:
    receipt = load_json(pathlib.Path(args.receipt))
    app = pathlib.Path(args.app).resolve()
    executable = app / "Contents" / "MacOS" / "Nostr VPN"
    cli = app / "Contents" / "Resources" / "nvpn"
    if (
        receipt.get("receiptSchema") not in (1, 2)
        or receipt.get("artifactType")
        != "macOS company Developer ID Release gate package"
        or receipt.get("companySigningVerified") is not True
    ):
        raise ValueError("macOS publication received the wrong gate receipt")
    for name, expected in (
        ("signingTeam", args.expected_team),
        ("signingIdentitySha1", args.expected_identity_sha1),
        ("signerCertificateSha256", args.expected_signer_sha256),
    ):
        if expected and receipt.get(name, "").lower() != expected.lower():
            raise ValueError(f"macOS publication receipt {name} is not pinned")
    for name, expected in (
        ("appGitSha", args.expected_app_head),
        ("appGitTree", args.expected_app_tree),
    ):
        if receipt.get(name) != expected:
            raise ValueError(f"macOS publication receipt {name} changed")
    if not app.is_dir() or not executable.is_file() or not cli.is_file():
        raise ValueError("macOS publication app payload is missing")
    companion = pathlib.Path(getattr(args, "hosted_admission", None) or app.parent / "hosted-admission.json")
    validate_receipt_admission(receipt, companion, app, allow_stapled=not args.require_gate_bundle_tree)
    if (
        args.require_gate_bundle_tree
        and tree_sha256(app) != receipt.get("appBundleTreeSha256")
    ):
        raise ValueError(
            "macOS publication app bundle differs from the exact gated bundle"
        )
    signature = inspect_signature(app, deep=True)
    expected_signature = {
        "cdhash": receipt.get("appCodeDirectoryHash"),
        "certificateSha1": receipt.get("signingIdentitySha1"),
        "certificateSha256": receipt.get("signerCertificateSha256"),
        "team": receipt.get("signingTeam"),
    }
    for name, expected in expected_signature.items():
        if signature.get(name) != expected:
            raise ValueError(
                f"macOS publication app {name} differs from the gated app"
            )
    if sha256_file(executable) != receipt.get("appExecutableSha256"):
        raise ValueError(
            "macOS publication executable bytes differ from the gated app"
        )
    if sha256_file(cli) != receipt.get("cliExecutableSha256"):
        raise ValueError(
            "macOS publication CLI bytes differ from the gated app"
        )
    print(
        json.dumps(
            {
                "appCodeDirectoryHash": signature["cdhash"],
                "appExecutableSha256": receipt["appExecutableSha256"],
                "cliExecutableSha256": receipt["cliExecutableSha256"],
            },
            sort_keys=True,
        )
    )


def add_common_arguments(command: argparse.ArgumentParser) -> None:
    command.add_argument("--hosted-admission")
    for name in (
        "receipt",
        "package",
        "app",
        "archive",
        "manual_join_fixture",
        "manual_join_driver",
        "service_toggle_driver",
        "component_proof",
        "app_root",
        "fips_root",
        "expected_app_head",
        "expected_app_tree",
        "expected_harness_head",
        "expected_harness_tree",
        "expected_fips_head",
        "expected_fips_tree",
        "expected_fips_version",
        "expected_team",
        "expected_identity_sha1",
        "expected_signer_sha256",
    ):
        command.add_argument(f"--{name.replace('_', '-')}", required=True)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    subparsers = result.add_subparsers(dest="command", required=True)
    certificate = subparsers.add_parser("resolve-certificate")
    certificate.add_argument("--identity-sha1", required=True)
    create = subparsers.add_parser("create")
    add_common_arguments(create)
    validate = subparsers.add_parser("validate")
    add_common_arguments(validate)
    validate.add_argument("--verification-output", required=True)
    publication = subparsers.add_parser("validate-published-app")
    publication.add_argument("--receipt", required=True)
    publication.add_argument("--app", required=True)
    publication.add_argument("--expected-app-head", required=True)
    publication.add_argument("--expected-app-tree", required=True)
    publication.add_argument("--require-gate-bundle-tree", action="store_true")
    publication.add_argument("--expected-team")
    publication.add_argument("--expected-identity-sha1")
    publication.add_argument("--expected-signer-sha256")
    publication.add_argument("--hosted-admission")
    return result


def main() -> int:
    args = parser().parse_args()
    try:
        if args.command == "resolve-certificate":
            print(resolve_certificate(args.identity_sha1))
        elif args.command == "create":
            create_receipt(args)
        elif args.command == "validate":
            validate_receipt(args)
        else:
            validate_published_app(args)
    except (
        OSError,
        ValueError,
        json.JSONDecodeError,
        subprocess.CalledProcessError,
    ) as error:
        print(f"macOS Release join artifact rejected: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
