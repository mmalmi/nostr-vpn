#!/usr/bin/env python3
"""Fail-closed orchestration for a post-gate nvpn fleet canary.

Hostnames and device identifiers belong in an ignored private inventory.  This
orchestrator validates the frozen candidate, exact checked-in SSH driver, and
artifacts, then validates a strict evidence protocol returned by that driver.
It never builds software and has no remote transport of its own.

The private driver is invoked as:

  DRIVER probe    --target TARGET_JSON --output OUTPUT_JSON
  DRIVER install  --target TARGET_JSON --artifact ARTIFACT
                  --receipt RECEIPT --expectations EXPECTATIONS_JSON
                  --output OUTPUT_JSON
  DRIVER rollback --target TARGET_JSON --expectations EXPECTATIONS_JSON
                  --output OUTPUT_JSON

Probe exit 75 means unreachable and exit 76 means access is unauthorized.
Install exit 77 means the roster authorization expired before any live target
mutation.  Any other non-zero exit is a hard failure.
Install is only invoked with both --execute and
NVPN_FLEET_INSTALL_AUTHORIZED=1.  The driver must not build remotely or alter a
network/config outside that explicitly authorized install transaction.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import os
import pathlib
import platform
import re
import secrets
import stat
import subprocess
import sys
import time
from typing import Any

from fleet_release_canary_evidence import (
    EvidenceError,
    exact as require_exact,
    expected_install_transition,
    false as require_false,
    positive as require_positive_int,
    true as require_true,
    validate_install_result,
    validate_probe,
    validate_result_evidence,
    validate_rollback,
)


HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$")
PLATFORMS = {"linux", "windows"}
ARCHES = {
    "linux": {"x86_64", "aarch64"},
    "windows": {"x86_64"},
}
DRIVER_RELATIVE_PATH = pathlib.Path("scripts/fleet_release_canary_ssh_driver.py")
DRIVER_HELPER_RELATIVE_PATHS = (
    pathlib.Path("scripts/fleet_release_canary_remote_linux.py"),
    pathlib.Path("scripts/fleet_release_canary_remote_windows.ps1"),
)
DRIVER_PROTOCOL = "nvpn-fleet-ssh-transactional-v2"
GATE_EVIDENCE_ID = "complete-release-gate"
GATE_EVIDENCE_KIND = "staged-release-attestation-v1"
GATE_VALIDATOR_RELATIVE_PATH = pathlib.Path(
    "scripts/fleet-release-gate-evidence.mjs"
)
GATE_VALIDATOR_TIMEOUT_SECONDS = 30
INSTALL_AUTHORIZATION_EXPIRED = 77
GATE_RECEIPT_KEYS = {
    "android": {
        "foreground_idle_cpu",
        "foreground_idle_cpu_raw",
        "install",
        "physical",
        "mobile_join",
        "wireguard_dns",
        "underlay_lifecycle",
        "replacement_singleton",
    },
    "ios": {
        "desktop_mobile_join",
        "frozen_archive",
        "join_variant",
        "mobile_artifact",
        "mobile_join",
        "wireguard_dns",
        "underlay_lifecycle",
    },
    "linux": {
        "arm64_cli",
        "artifact",
        "public_ui_join",
        "package_install",
        "network",
    },
    "macos": {
        "artifact",
        "network_artifact",
        "public_ui_join",
        "network",
    },
    "windows": {
        "artifact",
        "installer",
        "public_ui_join",
        "network",
    },
}


class CanaryError(RuntimeError):
    """A validation or execution error that must block the rollout."""


def fail(message: str) -> None:
    raise CanaryError(message)


def load_json(path: pathlib.Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        fail(f"{label} is not readable JSON: {error}")
    if not isinstance(value, dict):
        fail(f"{label} must be a JSON object")
    return value


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def require_regular_file(path: pathlib.Path, label: str) -> None:
    try:
        metadata = path.lstat()
    except OSError as error:
        fail(f"{label} is missing: {error}")
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        fail(f"{label} must be a regular non-symlink file")


def run(
    arguments: list[str],
    *,
    cwd: pathlib.Path | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        arguments,
        cwd=cwd,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if check and result.returncode != 0:
        details = result.stderr.strip() or result.stdout.strip()
        fail(f"command failed ({arguments[0]}): {details}")
    return result


def git_value(root: pathlib.Path, *arguments: str) -> str:
    return run(["git", "-C", str(root), *arguments]).stdout.strip()


def path_is_private(root: pathlib.Path, path: pathlib.Path) -> bool:
    try:
        relative = path.resolve().relative_to(root.resolve())
    except ValueError:
        return True
    result = run(
        ["git", "-C", str(root), "check-ignore", "-q", "--", str(relative)],
        check=False,
    )
    return result.returncode == 0


def require_private_path(
    root: pathlib.Path, path: pathlib.Path, label: str
) -> pathlib.Path:
    if not path.is_absolute():
        fail(f"{label} must use an absolute path")
    if not path_is_private(root, path):
        fail(f"{label} is inside the checkout but is not ignored")
    return path


def require_hex(value: Any, pattern: re.Pattern[str], label: str) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        fail(f"{label} is invalid")
    return value


def require_version(value: Any, label: str) -> str:
    if not isinstance(value, str) or VERSION.fullmatch(value) is None:
        fail(f"{label} is invalid")
    return value


def require_exact_keys(
    value: Any,
    expected: set[str],
    label: str,
) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        fail(f"{label} must contain exactly: {', '.join(sorted(expected))}")
    return value


def validate_checkout(
    root: pathlib.Path,
    fips_root: pathlib.Path,
    manifest: dict[str, Any],
) -> dict[str, str]:
    require_exact(manifest.get("schema"), 2, "fleet manifest schema")
    app_sha = require_hex(manifest.get("appGitSha"), HEX40, "appGitSha")
    app_tree = require_hex(manifest.get("appGitTree"), HEX40, "appGitTree")
    app_version = require_version(manifest.get("appVersion"), "appVersion")
    fips_sha = require_hex(manifest.get("fipsGitSha"), HEX40, "fipsGitSha")
    fips_tree = require_hex(manifest.get("fipsGitTree"), HEX40, "fipsGitTree")
    fips_version = require_version(manifest.get("fipsVersion"), "fipsVersion")

    require_exact(git_value(root, "rev-parse", "HEAD"), app_sha, "app HEAD")
    require_exact(git_value(root, "rev-parse", "HEAD^{tree}"), app_tree, "app tree")
    if git_value(root, "status", "--porcelain", "--untracked-files=all"):
        fail("app checkout must be clean before fleet canary")
    require_exact(git_value(fips_root, "rev-parse", "HEAD"), fips_sha, "FIPS HEAD")
    require_exact(
        git_value(fips_root, "rev-parse", "HEAD^{tree}"),
        fips_tree,
        "FIPS tree",
    )
    if git_value(fips_root, "status", "--porcelain", "--untracked-files=all"):
        fail("FIPS checkout must be clean before fleet canary")

    return {
        "appGitSha": app_sha,
        "appGitTree": app_tree,
        "appVersion": app_version,
        "fipsGitSha": fips_sha,
        "fipsGitTree": fips_tree,
        "fipsVersion": fips_version,
    }


def validate_bound_file(
    root: pathlib.Path,
    entry: dict[str, Any],
    label: str,
) -> pathlib.Path:
    raw_path = entry.get("path")
    if not isinstance(raw_path, str):
        fail(f"{label}.path is required")
    path = require_private_path(root, pathlib.Path(raw_path), f"{label}.path")
    require_regular_file(path, label)
    expected_hash = require_hex(entry.get("sha256"), HEX64, f"{label}.sha256")
    expected_size = require_positive_int(entry.get("size"), f"{label}.size")
    require_exact(sha256_file(path), expected_hash, f"{label} SHA-256")
    require_exact(path.stat().st_size, expected_size, f"{label} size")
    return path


def validate_gate_evidence(
    root: pathlib.Path,
    manifest: dict[str, Any],
    source: dict[str, str],
) -> dict[str, Any]:
    entries = manifest.get("gateEvidence")
    if not isinstance(entries, list) or len(entries) != 1:
        fail("fleet manifest requires exactly one complete release-gate evidence")
    value = require_exact_keys(
        entries[0],
        {"id", "kind", "path", "sha256", "size", "receiptPaths"},
        "gateEvidence[0]",
    )
    require_exact(value["id"], GATE_EVIDENCE_ID, "gateEvidence[0].id")
    require_exact(value["kind"], GATE_EVIDENCE_KIND, "gateEvidence[0].kind")
    release_path = validate_bound_file(
        root,
        value,
        f"gateEvidence[{GATE_EVIDENCE_ID}]",
    )
    paths = require_exact_keys(
        value["receiptPaths"],
        {"releaseGateSummary", "platforms"},
        "gateEvidence[0].receiptPaths",
    )
    summary_entry = require_exact_keys(
        paths["releaseGateSummary"],
        {"path", "sha256", "size"},
        "gateEvidence[0].receiptPaths.releaseGateSummary",
    )
    summary_path = validate_bound_file(
        root,
        summary_entry,
        "release-gate summary receipt",
    )
    platform_entries = require_exact_keys(
        paths["platforms"],
        set(GATE_RECEIPT_KEYS),
        "gateEvidence[0].receiptPaths.platforms",
    )
    platform_paths: dict[str, dict[str, str]] = {}
    for platform_name, expected_keys in GATE_RECEIPT_KEYS.items():
        receipts = require_exact_keys(
            platform_entries[platform_name],
            expected_keys,
            f"gateEvidence receiptPaths {platform_name}",
        )
        platform_paths[platform_name] = {}
        for receipt_name in sorted(expected_keys):
            entry = require_exact_keys(
                receipts[receipt_name],
                {"path", "sha256", "size"},
                f"gateEvidence receiptPaths {platform_name}.{receipt_name}",
            )
            platform_paths[platform_name][receipt_name] = str(
                validate_bound_file(
                    root,
                    entry,
                    f"release-gate receipt {platform_name}.{receipt_name}",
                )
            )

    validator = (root / GATE_VALIDATOR_RELATIVE_PATH).resolve()
    require_regular_file(validator, "fleet release-gate validator")
    tracked = run(
        [
            "git",
            "-C",
            str(root),
            "ls-files",
            "--error-unmatch",
            "--",
            GATE_VALIDATOR_RELATIVE_PATH.as_posix(),
        ],
        check=False,
    )
    if tracked.returncode != 0:
        fail("fleet release-gate validator must be tracked by the exact checkout")
    request = {
        "candidateRoot": str(root),
        "releasePath": str(release_path),
        "source": source,
        "receiptPaths": {
            "releaseGateSummary": str(summary_path),
            "platforms": platform_paths,
        },
    }
    try:
        result = subprocess.run(
            ["node", str(validator)],
            input=json.dumps(request, separators=(",", ":"), sort_keys=True),
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=GATE_VALIDATOR_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        fail(
            "complete release-gate evidence validation exceeded "
            f"{GATE_VALIDATOR_TIMEOUT_SECONDS} seconds"
        )
    if result.returncode != 0:
        fail(
            "complete release-gate evidence failed semantic validation: "
            f"{result.stderr.strip() or result.stdout.strip()}"
        )
    try:
        validated = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        fail(f"fleet release-gate validator returned invalid JSON: {error}")
    validated = require_exact_keys(
        validated,
        {
            "schema",
            "release",
            "assets",
            "assetProofs",
            "assetSetSha256",
            "releaseGateSummarySha256",
            "platformGateReceipts",
        },
        "fleet release-gate validator result",
    )
    require_exact(validated["schema"], 1, "fleet release-gate validator schema")
    release = require_exact_keys(
        validated["release"],
        {"id", "tag", "title", "commit", "draft"},
        "fleet release-gate validator release",
    )
    expected_tag = f"v{source['appVersion']}"
    for field in ("id", "tag", "title"):
        require_exact(
            release[field],
            expected_tag,
            f"fleet release-gate release.{field}",
        )
    require_exact(
        release["commit"],
        source["appGitSha"],
        "fleet release-gate release.commit",
    )
    if not isinstance(release["draft"], bool):
        fail("fleet release-gate release.draft must be a boolean")
    require_hex(
        validated["assetSetSha256"],
        HEX64,
        "fleet release-gate assetSetSha256",
    )
    require_hex(
        validated["releaseGateSummarySha256"],
        HEX64,
        "fleet release-gate releaseGateSummarySha256",
    )
    require_exact_keys(
        validated["platformGateReceipts"],
        set(GATE_RECEIPT_KEYS),
        "fleet release-gate platformGateReceipts",
    )
    if not isinstance(validated["assets"], list) or not validated["assets"]:
        fail("fleet release-gate validator returned no staged assets")
    assets: dict[str, dict[str, Any]] = {}
    for index, asset_value in enumerate(validated["assets"]):
        asset = require_exact_keys(
            asset_value,
            {"path", "sha256", "size"},
            f"fleet release-gate asset[{index}]",
        )
        path_value = asset["path"]
        if not isinstance(path_value, str) or not path_value.startswith("assets/"):
            fail(f"fleet release-gate asset[{index}].path is invalid")
        if path_value in assets:
            fail(f"duplicate fleet release-gate asset path: {path_value}")
        require_hex(
            asset["sha256"],
            HEX64,
            f"fleet release-gate asset[{path_value}].sha256",
        )
        require_positive_int(
            asset["size"],
            f"fleet release-gate asset[{path_value}].size",
        )
        assets[path_value] = asset
    proofs = validated["assetProofs"]
    if not isinstance(proofs, dict) or set(proofs) != set(assets):
        fail("fleet release-gate asset proofs do not bind every staged asset")
    require_exact(
        sha256_file(release_path),
        value["sha256"],
        "semantically validated release manifest remained stable",
    )
    return {
        "id": GATE_EVIDENCE_ID,
        "releaseManifestSha256": value["sha256"],
        "assets": assets,
        "proofs": proofs,
    }


def validate_driver(
    root: pathlib.Path,
    manifest: dict[str, Any],
) -> tuple[pathlib.Path, str]:
    value = manifest.get("driver")
    if not isinstance(value, dict):
        fail("fleet manifest requires the frozen production driver")
    require_exact(value.get("protocol"), DRIVER_PROTOCOL, "fleet driver protocol")
    expected = (root / DRIVER_RELATIVE_PATH).resolve()
    raw_path = value.get("path")
    if not isinstance(raw_path, str):
        fail("fleet driver path is required")
    path = pathlib.Path(raw_path)
    if not path.is_absolute() or path.resolve() != expected:
        fail(
            "fleet driver must be the checked-in " f"{DRIVER_RELATIVE_PATH.as_posix()}"
        )
    require_regular_file(path, "fleet driver")
    if not os.access(path, os.X_OK):
        fail("fleet driver must be executable")
    tracked = run(
        [
            "git",
            "-C",
            str(root),
            "ls-files",
            "--error-unmatch",
            "--",
            DRIVER_RELATIVE_PATH.as_posix(),
        ],
        check=False,
    )
    if tracked.returncode != 0:
        fail("fleet driver must be tracked by the exact clean checkout")
    expected_hash = require_hex(value.get("sha256"), HEX64, "fleet driver sha256")
    expected_size = require_positive_int(value.get("size"), "fleet driver size")
    require_exact(sha256_file(path), expected_hash, "fleet driver SHA-256")
    require_exact(path.stat().st_size, expected_size, "fleet driver size")
    helpers = value.get("helpers")
    if not isinstance(helpers, list) or len(helpers) != len(
        DRIVER_HELPER_RELATIVE_PATHS
    ):
        fail("fleet driver helpers must bind both checked-in platform adapters")
    helpers_by_path: dict[str, dict[str, Any]] = {}
    for item in helpers:
        if not isinstance(item, dict) or not isinstance(item.get("path"), str):
            fail("fleet driver helper entries must be objects with paths")
        item_path = pathlib.Path(item["path"])
        if not item_path.is_absolute():
            fail("fleet driver helper paths must be absolute")
        helpers_by_path[str(item_path.resolve())] = item
    if len(helpers_by_path) != len(helpers):
        fail("fleet driver helper paths must be unique")
    for relative in DRIVER_HELPER_RELATIVE_PATHS:
        helper_path = (root / relative).resolve()
        entry = helpers_by_path.get(str(helper_path))
        if entry is None:
            fail(f"fleet driver helper is not bound: {relative.as_posix()}")
        require_regular_file(helper_path, f"fleet driver helper {relative}")
        tracked = run(
            [
                "git",
                "-C",
                str(root),
                "ls-files",
                "--error-unmatch",
                "--",
                relative.as_posix(),
            ],
            check=False,
        )
        if tracked.returncode != 0:
            fail(f"fleet driver helper must be tracked: {relative.as_posix()}")
        helper_hash = require_hex(
            entry.get("sha256"),
            HEX64,
            f"fleet driver helper {relative} sha256",
        )
        helper_size = require_positive_int(
            entry.get("size"), f"fleet driver helper {relative} size"
        )
        require_exact(
            sha256_file(helper_path),
            helper_hash,
            f"fleet driver helper {relative} SHA-256",
        )
        require_exact(
            helper_path.stat().st_size,
            helper_size,
            f"fleet driver helper {relative} size",
        )
    return path, expected_hash


def validate_artifacts(
    root: pathlib.Path,
    manifest: dict[str, Any],
    source: dict[str, str],
    gate_evidence: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    entries = manifest.get("artifacts")
    if not isinstance(entries, list) or not entries:
        fail("fleet manifest requires frozen artifacts")
    artifacts: dict[str, dict[str, Any]] = {}
    for index, value in enumerate(entries):
        if not isinstance(value, dict):
            fail(f"artifacts[{index}] must be an object")
        artifact_id = value.get("id")
        if not isinstance(artifact_id, str) or not artifact_id.strip():
            fail(f"artifacts[{index}].id is required")
        if artifact_id in artifacts:
            fail(f"duplicate artifact id: {artifact_id}")
        target_platform = value.get("platform")
        target_arch = value.get("arch")
        if target_platform not in PLATFORMS:
            fail(f"artifact {artifact_id} has unsupported platform")
        if target_arch not in ARCHES[target_platform]:
            fail(f"artifact {artifact_id} has unsupported architecture")
        artifact_path = validate_bound_file(root, value, f"artifact[{artifact_id}]")
        receipt_value = value.get("receipt")
        if not isinstance(receipt_value, dict):
            fail(f"artifact {artifact_id} requires an exact receipt")
        receipt_path = validate_bound_file(
            root, receipt_value, f"artifact[{artifact_id}].receipt"
        )
        receipt = load_json(receipt_path, f"artifact {artifact_id} receipt")
        for field, expected in source.items():
            require_exact(
                receipt.get(field),
                expected,
                f"artifact {artifact_id} receipt {field}",
            )
        require_exact(
            receipt.get("platform"),
            target_platform,
            f"artifact {artifact_id} receipt platform",
        )
        require_exact(
            receipt.get("arch"),
            target_arch,
            f"artifact {artifact_id} receipt arch",
        )
        require_exact(
            receipt.get("artifactSha256"),
            value.get("sha256"),
            f"artifact {artifact_id} receipt artifactSha256",
        )
        require_exact(
            receipt.get("artifactSize"),
            value.get("size"),
            f"artifact {artifact_id} receipt artifactSize",
        )
        installed_hash = require_hex(
            receipt.get("installedBinarySha256"),
            HEX64,
            f"artifact {artifact_id} receipt installedBinarySha256",
        )
        payload = value.get("installPayload")
        if not isinstance(payload, dict):
            fail(f"artifact {artifact_id} requires installPayload")
        payload_format = payload.get("format")
        allowed_formats = (
            {"executable", "tar-gz"}
            if target_platform == "linux"
            else {"executable", "zip"}
        )
        if payload_format not in allowed_formats:
            fail(f"artifact {artifact_id} installPayload.format is invalid")
        member = payload.get("executableMember")
        if payload_format == "executable":
            if member not in (None, ""):
                fail(
                    f"artifact {artifact_id} executable payload cannot name "
                    "an archive member"
                )
            member = ""
        elif (
            not isinstance(member, str)
            or not member.strip()
            or member.startswith(("/", "\\"))
            or ".." in pathlib.PurePosixPath(member).parts
        ):
            fail(
                f"artifact {artifact_id} installPayload.executableMember " "is invalid"
            )
        companions = payload.get("companions", [])
        if not isinstance(companions, list):
            fail(f"artifact {artifact_id} installPayload.companions is invalid")
        installed_payloads = receipt.get("installedPayloads")
        if not isinstance(installed_payloads, dict):
            fail(f"artifact {artifact_id} receipt lacks installedPayloads")
        executable_key = member or "executable"
        require_exact(
            installed_payloads.get(executable_key),
            installed_hash,
            f"artifact {artifact_id} receipt executable payload",
        )
        validated_companions: list[dict[str, str]] = []
        seen_members = {executable_key}
        for companion_index, companion in enumerate(companions):
            if not isinstance(companion, dict):
                fail(
                    f"artifact {artifact_id} companion {companion_index} "
                    "must be an object"
                )
            companion_member = companion.get("member")
            if (
                not isinstance(companion_member, str)
                or not companion_member.strip()
                or companion_member.startswith(("/", "\\"))
                or ".." in pathlib.PurePosixPath(companion_member).parts
                or companion_member in seen_members
            ):
                fail(
                    f"artifact {artifact_id} companion {companion_index} "
                    "member is invalid"
                )
            seen_members.add(companion_member)
            companion_hash = require_hex(
                companion.get("sha256"),
                HEX64,
                f"artifact {artifact_id} companion {companion_member} sha256",
            )
            require_exact(
                installed_payloads.get(companion_member),
                companion_hash,
                f"artifact {artifact_id} receipt companion {companion_member}",
            )
            validated_companions.append(
                {"member": companion_member, "sha256": companion_hash}
            )
        receipt_gate_ids = receipt.get("gateEvidenceIds")
        if receipt_gate_ids != [gate_evidence["id"]]:
            fail(f"artifact {artifact_id} receipt has invalid gate evidence")
        release_asset_path = receipt.get("releaseAssetPath")
        if not isinstance(release_asset_path, str):
            fail(f"artifact {artifact_id} receipt lacks releaseAssetPath")
        release_asset = gate_evidence["assets"].get(release_asset_path)
        proof = gate_evidence["proofs"].get(release_asset_path)
        if release_asset is None or not isinstance(proof, dict):
            fail(f"artifact {artifact_id} is not bound to a staged release asset")
        require_exact(
            proof.get("platform"),
            target_platform,
            f"artifact {artifact_id} release proof platform",
        )
        require_exact(
            proof.get("artifact_sha256"),
            release_asset["sha256"],
            f"artifact {artifact_id} release proof artifact SHA-256",
        )
        proof_payloads = proof.get("payloads")
        if not isinstance(proof_payloads, dict) or not proof_payloads:
            fail(f"artifact {artifact_id} release proof has no payloads")
        release_payload_labels = receipt.get("releasePayloadLabels")
        if (
            not isinstance(release_payload_labels, dict)
            or set(release_payload_labels) != set(installed_payloads)
        ):
            fail(
                f"artifact {artifact_id} receipt releasePayloadLabels "
                "must map every installed payload exactly once"
            )
        payload_labels: list[str] = []
        for installed_member, payload_label in release_payload_labels.items():
            if not isinstance(payload_label, str) or not payload_label:
                fail(
                    f"artifact {artifact_id} release payload label "
                    f"for {installed_member} is invalid"
                )
            payload_labels.append(payload_label)
            require_exact(
                installed_payloads[installed_member],
                proof_payloads.get(payload_label),
                f"artifact {artifact_id} installed payload {installed_member} "
                "release proof",
            )
        if len(set(payload_labels)) != len(payload_labels):
            fail(
                f"artifact {artifact_id} receipt releasePayloadLabels "
                "must map every installed payload exactly once"
            )
        if payload_format == "executable":
            require_exact(
                value.get("sha256"),
                installed_hash,
                f"artifact {artifact_id} executable artifact SHA-256",
            )
        else:
            require_exact(
                value.get("sha256"),
                release_asset["sha256"],
                f"artifact {artifact_id} staged release asset SHA-256",
            )
            require_exact(
                value.get("size"),
                release_asset["size"],
                f"artifact {artifact_id} staged release asset size",
            )
        artifacts[artifact_id] = {
            **value,
            "_path": artifact_path,
            "_receipt_path": receipt_path,
            "_installed_hash": installed_hash,
            "_install_payload": {
                "format": payload_format,
                "executableMember": member,
                "companions": validated_companions,
            },
        }
    return artifacts


def validate_inventory_freshness(inventory: dict[str, Any]) -> int:
    freshness = inventory.get("rosterFreshness")
    if not isinstance(freshness, dict) or set(freshness) != {
        "maxAgeSeconds",
        "validatedAt",
    }:
        fail("fleet inventory rosterFreshness fields are invalid")
    max_age = freshness.get("maxAgeSeconds")
    if (
        not isinstance(max_age, int)
        or isinstance(max_age, bool)
        or max_age < 300
        or max_age > 1800
    ):
        fail("fleet inventory max evidence age must be between 300 and 1800")
    snapshot = inventory.get("rosterSnapshot")
    if not isinstance(snapshot, dict):
        fail("fleet inventory rosterSnapshot is missing")
    timestamps: list[tuple[str, Any]] = [
        ("rosterFreshness.validatedAt", freshness.get("validatedAt")),
        ("rosterSnapshot.capturedAt", snapshot.get("capturedAt")),
    ]
    coverage = inventory.get("rosterCoverage")
    if not isinstance(coverage, list) or not coverage:
        fail("fleet inventory rosterCoverage is missing")
    timestamps.extend(
        (
            f"rosterCoverage[{index}].observedAt",
            row.get("observedAt") if isinstance(row, dict) else None,
        )
        for index, row in enumerate(coverage)
    )
    now = int(time.time())
    deadline = now + max_age
    for label, value in timestamps:
        if (
            not isinstance(value, int)
            or isinstance(value, bool)
            or value <= 0
            or value > now + 300
        ):
            fail(f"fleet inventory {label} is invalid")
        deadline = min(deadline, value + max_age)
    if now > deadline:
        fail("fleet roster evidence is stale; no target may be installed")
    return deadline


def require_fresh_install_authorization(deadline: int) -> None:
    if int(time.time()) > deadline:
        fail("fleet roster evidence expired before target install")


def validate_inventory(
    inventory: dict[str, Any],
    artifacts: dict[str, dict[str, Any]],
) -> tuple[list[dict[str, Any]], int, int]:
    require_exact(inventory.get("schema"), 2, "fleet inventory schema")
    require_true(inventory.get("excludeCurrentHost"), "excludeCurrentHost")
    freshness_deadline = validate_inventory_freshness(inventory)
    targets = inventory.get("targets")
    if not isinstance(targets, list) or not targets:
        fail("fleet inventory requires targets")
    seen: set[str] = set()
    validated: list[dict[str, Any]] = []
    for index, target in enumerate(targets):
        if not isinstance(target, dict):
            fail(f"targets[{index}] must be an object")
        target_id = target.get("id")
        if not isinstance(target_id, str) or not target_id.strip():
            fail(f"targets[{index}].id is required")
        if target_id in seen:
            fail(f"duplicate fleet target id: {target_id}")
        seen.add(target_id)
        artifact_id = target.get("artifact")
        if artifact_id not in artifacts:
            fail(f"target {target_id} references an unknown artifact")
        artifact = artifacts[artifact_id]
        require_exact(
            target.get("platform"),
            artifact["platform"],
            f"target {target_id} platform",
        )
        require_exact(target.get("arch"), artifact["arch"], f"target {target_id} arch")
        transport = target.get("transport")
        if not isinstance(transport, dict):
            fail(f"target {target_id} requires transport")
        require_exact(
            transport.get("kind"), "ssh", f"target {target_id} transport.kind"
        )
        host_alias = transport.get("hostAlias")
        if (
            not isinstance(host_alias, str)
            or re.fullmatch(r"[A-Za-z0-9_.@:-]+", host_alias) is None
        ):
            fail(f"target {target_id} transport.hostAlias is invalid")
        deployment = target.get("deployment")
        if not isinstance(deployment, dict):
            fail(f"target {target_id} requires deployment")
        authorization = deployment.get("authorization")
        if authorization not in {"install", "report-only"}:
            fail(
                f"target {target_id} deployment.authorization must be "
                "install or report-only"
            )
        if authorization == "report-only":
            reason = deployment.get("reason")
            if not isinstance(reason, str) or not reason.strip():
                fail(f"target {target_id} report-only deployment requires reason")
        expected = target.get("expected")
        if not isinstance(expected, dict):
            fail(f"target {target_id} requires frozen expected identity")
        for field in (
            "machineIdentitySha256",
            "configSha256",
            "signedRosterStoreSha256",
            "rosterIdentitySha256",
            "localDeviceIdentitySha256",
            "networkIdentitySha256",
        ):
            require_hex(
                expected.get(field),
                HEX64,
                f"target {target_id} expected.{field}",
            )
        roster_count = expected.get("rosterPeerCount")
        if (
            not isinstance(roster_count, int)
            or isinstance(roster_count, bool)
            or roster_count < 0
        ):
            fail(
                f"target {target_id} expected.rosterPeerCount must be "
                "a non-negative integer"
            )
        checks = target.get("checks")
        if not isinstance(checks, dict):
            fail(f"target {target_id} requires checks")
        for field in ("payloadTarget", "dnsName", "directUrl"):
            if not isinstance(checks.get(field), str) or not checks[field].strip():
                fail(f"target {target_id} checks.{field} is required")
        validated.append(target)
    parallel = inventory.get("parallelProbes", 4)
    if not isinstance(parallel, int) or isinstance(parallel, bool):
        fail("parallelProbes must be an integer")
    if parallel < 1 or parallel > 16:
        fail("parallelProbes must be between 1 and 16")
    return validated, parallel, freshness_deadline


def local_machine_identity_sha256() -> str:
    system = platform.system()
    raw = ""
    if system == "Darwin":
        result = run(["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"], check=False)
        match = re.search(r'"IOPlatformUUID"\s*=\s*"([^"]+)"', result.stdout)
        if match:
            raw = match.group(1)
    elif system == "Linux":
        for candidate in (
            pathlib.Path("/etc/machine-id"),
            pathlib.Path("/var/lib/dbus/machine-id"),
        ):
            if candidate.is_file():
                raw = candidate.read_text(encoding="utf-8").strip()
                if raw:
                    break
    elif system == "Windows":
        result = run(
            [
                "reg",
                "query",
                r"HKLM\\SOFTWARE\\Microsoft\\Cryptography",
                "/v",
                "MachineGuid",
            ],
            check=False,
        )
        match = re.search(r"MachineGuid\s+REG_SZ\s+(\S+)", result.stdout)
        if match:
            raw = match.group(1)
    if not raw:
        fail("could not derive the current host identity")
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def target_file(evidence_dir: pathlib.Path, target: dict[str, Any]) -> pathlib.Path:
    digest = hashlib.sha256(target["id"].encode("utf-8")).hexdigest()[:16]
    path = evidence_dir / f"target-{digest}.json"
    path.write_text(json.dumps(target, sort_keys=True) + "\n", encoding="utf-8")
    path.chmod(0o600)
    return path


def invoke_driver(
    driver: pathlib.Path,
    action: str,
    target_path: pathlib.Path,
    output: pathlib.Path,
    *,
    artifact: dict[str, Any] | None = None,
    expectations: pathlib.Path | None = None,
) -> subprocess.CompletedProcess[str]:
    arguments = [
        str(driver),
        action,
        "--target",
        str(target_path),
        "--output",
        str(output),
    ]
    if artifact is not None:
        arguments.extend(
            [
                "--artifact",
                str(artifact["_path"]),
                "--receipt",
                str(artifact["_receipt_path"]),
            ]
        )
    if expectations is not None:
        arguments.extend(["--expectations", str(expectations)])
    return run(arguments, check=False)


def write_json(path: pathlib.Path, value: dict[str, Any]) -> None:
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def load_driver_evidence(
    output: pathlib.Path,
    evidence_dir: pathlib.Path,
    label: str,
) -> dict[str, Any]:
    require_regular_file(output, label)
    value = load_json(output, label)
    binding = value.get("rawReceipt")
    if not isinstance(binding, dict):
        fail(f"{label} requires a rawReceipt binding")
    require_exact_keys(
        binding,
        {"path", "sha256", "size"},
        f"{label} rawReceipt",
    )
    raw_path_value = binding.get("path")
    if not isinstance(raw_path_value, str):
        fail(f"{label} rawReceipt.path is required")
    raw_path = pathlib.Path(raw_path_value)
    if not raw_path.is_absolute():
        fail(f"{label} rawReceipt.path must be absolute")
    try:
        raw_path.resolve().relative_to(evidence_dir.resolve())
    except ValueError:
        fail(f"{label} rawReceipt.path escapes the private evidence directory")
    require_regular_file(raw_path, f"{label} raw receipt")
    expected_hash = require_hex(
        binding.get("sha256"), HEX64, f"{label} rawReceipt.sha256"
    )
    expected_size = require_positive_int(
        binding.get("size"), f"{label} rawReceipt.size"
    )
    require_exact(
        sha256_file(raw_path),
        expected_hash,
        f"{label} raw receipt SHA-256",
    )
    require_exact(
        raw_path.stat().st_size,
        expected_size,
        f"{label} raw receipt size",
    )
    raw_value = load_json(raw_path, f"{label} raw receipt")
    semantic_value = {key: item for key, item in value.items() if key != "rawReceipt"}
    require_exact(
        raw_value,
        semantic_value,
        f"{label} raw receipt contents",
    )
    return value


def probe_report_row(
    target_id: str,
    status: str,
    details: Any,
) -> dict[str, Any]:
    row: dict[str, Any] = {"id": target_id, "status": status}
    if isinstance(details, dict) and "_rawReceipt" in details:
        row["evidence"] = validate_result_evidence(
            {"probe": details["_rawReceipt"]},
            {"probe"},
            f"target {target_id} result evidence",
        )
    return row


def expired_install_report_row(
    target_id: str,
    probe: dict[str, Any],
    error: str,
) -> dict[str, Any]:
    row = probe_report_row(target_id, "failed-expired", probe)
    row["installError"] = error
    return row


def build_probe_expectations(
    evidence_dir: pathlib.Path,
    source: dict[str, str],
    artifact: dict[str, Any],
    target: dict[str, Any],
) -> pathlib.Path:
    digest = hashlib.sha256(target["id"].encode("utf-8")).hexdigest()[:16]
    path = evidence_dir / f"probe-expectations-{digest}.json"
    write_json(
        path,
        {
            "schema": 2,
            "kind": "candidate-identity-probe-v1",
            **source,
            "probeId": secrets.token_hex(16),
            "artifactSha256": artifact["sha256"],
            "artifactSize": artifact["size"],
            "installedBinarySha256": artifact["_installed_hash"],
            "installPayload": artifact["_install_payload"],
            "prohibitRemoteBuild": True,
            "requireReadOnly": True,
        },
    )
    path.chmod(0o600)
    return path


def build_expectations(
    evidence_dir: pathlib.Path,
    source: dict[str, str],
    artifact: dict[str, Any],
    target: dict[str, Any],
    probe: dict[str, Any],
    manifest_hash: str,
    inventory_hash: str,
    freshness_deadline: int,
) -> pathlib.Path:
    digest = hashlib.sha256(target["id"].encode("utf-8")).hexdigest()[:16]
    path = evidence_dir / f"expectations-{digest}.json"
    transaction_id = secrets.token_hex(16)
    write_json(
        path,
        {
            "schema": 2,
            **source,
            "transactionId": transaction_id,
            "manifestSha256": manifest_hash,
            "inventorySha256": inventory_hash,
            "rosterFreshnessDeadline": freshness_deadline,
            "artifactSha256": artifact["sha256"],
            "artifactSize": artifact["size"],
            "installedBinarySha256": artifact["_installed_hash"],
            "installTransition": expected_install_transition(
                probe,
                artifact["_installed_hash"],
            ),
            "installPayload": artifact["_install_payload"],
            "preinstallProbe": {
                field: probe[field]
                for field in (
                    "probeBinarySha256",
                    "probeAppVersion",
                    "probeFipsCoreVersion",
                )
            },
            "expected": target["expected"],
            "checks": target["checks"],
            "prohibitRemoteBuild": True,
            "requireDirectModeAfter": True,
            "requireSingleServiceProcess": True,
            "requireRestartDurability": True,
            "requireRollback": True,
            "requireDurableSnapshot": True,
            "requireDurableJournal": True,
        },
    )
    path.chmod(0o600)
    return path


def prepare(
    args: argparse.Namespace,
) -> tuple[
    pathlib.Path,
    dict[str, str],
    dict[str, dict[str, Any]],
    list[dict[str, Any]],
    int,
    int,
    str,
    str,
    pathlib.Path,
    str,
    str,
]:
    root = pathlib.Path(args.root).resolve()
    fips_root = pathlib.Path(args.fips_root).resolve()
    inventory_path = require_private_path(
        root, pathlib.Path(args.inventory), "fleet inventory"
    )
    manifest_path = require_private_path(
        root, pathlib.Path(args.manifest), "fleet manifest"
    )
    evidence_dir = require_private_path(
        root, pathlib.Path(args.evidence_dir), "fleet evidence directory"
    )
    require_regular_file(inventory_path, "fleet inventory")
    require_regular_file(manifest_path, "fleet manifest")
    evidence_dir.mkdir(parents=True, exist_ok=True)
    inventory = load_json(inventory_path, "fleet inventory")
    manifest = load_json(manifest_path, "fleet manifest")
    inventory_hash = sha256_file(inventory_path)
    require_exact(
        manifest.get("inventorySha256"),
        inventory_hash,
        "fleet manifest frozen inventory SHA-256",
    )
    source = validate_checkout(root, fips_root, manifest)
    driver, driver_hash = validate_driver(root, manifest)
    gate_evidence = validate_gate_evidence(root, manifest, source)
    artifacts = validate_artifacts(root, manifest, source, gate_evidence)
    targets, parallel, freshness_deadline = validate_inventory(
        inventory,
        artifacts,
    )
    return (
        root,
        source,
        artifacts,
        targets,
        parallel,
        freshness_deadline,
        sha256_file(manifest_path),
        inventory_hash,
        driver,
        driver_hash,
        gate_evidence["releaseManifestSha256"],
    )


def plan(args: argparse.Namespace) -> int:
    (
        _root,
        source,
        artifacts,
        targets,
        parallel,
        _freshness_deadline,
        manifest_hash,
        inventory_hash,
        _driver,
        driver_hash,
        release_gate_manifest_hash,
    ) = prepare(args)
    report = {
        "schema": 2,
        "mode": "plan",
        "status": "planned",
        "manifestSha256": manifest_hash,
        "inventorySha256": inventory_hash,
        "driverSha256": driver_hash,
        "releaseGateManifestSha256": release_gate_manifest_hash,
        **source,
        "parallelProbes": parallel,
        "targets": [
            {
                "id": target["id"],
                "platform": target["platform"],
                "arch": target["arch"],
                "artifact": target["artifact"],
                "artifactSha256": artifacts[target["artifact"]]["sha256"],
                "authorization": target["deployment"]["authorization"],
                "status": "planned",
            }
            for target in targets
        ],
    }
    write_json(pathlib.Path(args.evidence_dir) / "fleet-canary-plan.json", report)
    print(
        f"fleet canary plan validated for {len(targets)} target(s); no contact or mutation"
    )
    return 0


def execute(args: argparse.Namespace) -> int:
    if os.environ.get("NVPN_FLEET_INSTALL_AUTHORIZED") != "1":
        fail("execute requires NVPN_FLEET_INSTALL_AUTHORIZED=1")
    (
        root,
        source,
        artifacts,
        targets,
        parallel,
        freshness_deadline,
        manifest_hash,
        inventory_hash,
        driver,
        driver_hash,
        release_gate_manifest_hash,
    ) = prepare(args)

    evidence_dir = pathlib.Path(args.evidence_dir).resolve()
    local_identity = local_machine_identity_sha256()
    target_paths = {
        target["id"]: target_file(evidence_dir, target) for target in targets
    }
    probe_results: dict[str, dict[str, Any]] = {}

    def probe_one(target: dict[str, Any]) -> tuple[str, str, Any]:
        if target["expected"]["machineIdentitySha256"] == local_identity:
            return target["id"], "skipped-current-host", None
        artifact = artifacts[target["artifact"]]
        digest = hashlib.sha256(target["id"].encode("utf-8")).hexdigest()[:16]
        output = evidence_dir / f"probe-{digest}.json"
        output.unlink(missing_ok=True)
        probe_expectations = build_probe_expectations(
            evidence_dir,
            source,
            artifact,
            target,
        )
        result = invoke_driver(
            driver,
            "probe",
            target_paths[target["id"]],
            output,
            artifact=artifact,
            expectations=probe_expectations,
        )
        if result.returncode == 75:
            return target["id"], "skipped-unreachable", None
        if result.returncode == 76:
            return target["id"], "skipped-unauthorized", None
        if result.returncode != 0:
            return target["id"], "probe-failed", result.stderr.strip()
        try:
            evidence = load_driver_evidence(
                output,
                evidence_dir,
                f"probe evidence for {target['id']}",
            )
            snapshot = validate_probe(
                evidence,
                target,
                artifact,
                source,
            )
            snapshot["_rawReceipt"] = dict(evidence["rawReceipt"])
        except (CanaryError, EvidenceError) as error:
            return target["id"], "probe-failed", str(error)
        if snapshot["machineIdentitySha256"] == local_identity:
            return target["id"], "skipped-current-host", snapshot
        if target["deployment"]["authorization"] != "install":
            return target["id"], "skipped-unauthorized", snapshot
        return target["id"], "reachable", snapshot

    with concurrent.futures.ThreadPoolExecutor(max_workers=parallel) as executor:
        futures = [executor.submit(probe_one, target) for target in targets]
        for future in concurrent.futures.as_completed(futures):
            target_id, status, details = future.result()
            probe_results[target_id] = {"status": status, "details": details}

    identities: dict[str, str] = {}
    for target in targets:
        probe = probe_results[target["id"]]
        if probe["status"] != "reachable":
            continue
        identity = probe["details"]["machineIdentitySha256"]
        if identity in identities:
            fail(
                "fleet inventory aliases the same remote machine as "
                f"{identities[identity]} and {target['id']}"
            )
        identities[identity] = target["id"]

    report_targets: list[dict[str, Any]] = []
    hard_probe_failures = [
        target["id"]
        for target in targets
        if probe_results[target["id"]]["status"] == "probe-failed"
    ]
    if hard_probe_failures:
        for target in targets:
            probe = probe_results[target["id"]]
            report_targets.append(
                probe_report_row(target["id"], probe["status"], probe["details"])
            )
        write_json(
            evidence_dir / "fleet-canary-result.json",
            {
                "schema": 2,
                "mode": "execute",
                "status": "failed-preflight",
                "manifestSha256": manifest_hash,
                "inventorySha256": inventory_hash,
                "driverSha256": driver_hash,
                "releaseGateManifestSha256": release_gate_manifest_hash,
                **source,
                "targets": report_targets,
            },
        )
        fail("fleet probe failed; no target was installed")

    rollout_failed = False
    blocked_status = "blocked-by-prior-failure"
    for target in targets:
        probe = probe_results[target["id"]]
        if probe["status"] != "reachable":
            report_targets.append(
                probe_report_row(target["id"], probe["status"], probe["details"])
            )
            continue
        if rollout_failed:
            report_targets.append(
                probe_report_row(
                    target["id"],
                    blocked_status,
                    probe["details"],
                )
            )
            continue
        try:
            require_fresh_install_authorization(freshness_deadline)
        except CanaryError as error:
            report_targets.append(
                expired_install_report_row(
                    target["id"],
                    probe["details"],
                    str(error),
                )
            )
            rollout_failed = True
            blocked_status = "blocked-by-expired-authorization"
            continue
        artifact = artifacts[target["artifact"]]
        probe_snapshot = probe["details"]
        expectations = build_expectations(
            evidence_dir,
            source,
            artifact,
            target,
            probe_snapshot,
            manifest_hash,
            inventory_hash,
            freshness_deadline,
        )
        expectation_value = load_json(expectations, f"expectations for {target['id']}")
        transaction_id = expectation_value["transactionId"]
        digest = hashlib.sha256(target["id"].encode("utf-8")).hexdigest()[:16]
        install_output = evidence_dir / f"install-{digest}.json"
        install_output.unlink(missing_ok=True)
        install_result = invoke_driver(
            driver,
            "install",
            target_paths[target["id"]],
            install_output,
            artifact=artifact,
            expectations=expectations,
        )
        if install_result.returncode == INSTALL_AUTHORIZATION_EXPIRED:
            report_targets.append(
                expired_install_report_row(
                    target["id"],
                    probe_snapshot,
                    install_result.stderr.strip()
                    or "fleet roster evidence expired before remote install mutation",
                )
            )
            rollout_failed = True
            blocked_status = "blocked-by-expired-authorization"
            continue
        install_error = ""
        install_binding: dict[str, Any] | None = None
        try:
            if install_result.returncode != 0:
                fail(install_result.stderr.strip() or "driver install failed")
            install_evidence = load_driver_evidence(
                install_output,
                evidence_dir,
                f"install evidence for {target['id']}",
            )
            install_binding = dict(install_evidence["rawReceipt"])
            validate_install_result(
                install_evidence,
                target,
                artifact,
                source,
                probe_snapshot,
                transaction_id,
            )
        except (CanaryError, EvidenceError) as error:
            install_error = str(error)

        if not install_error:
            report_targets.append(
                {
                    "id": target["id"],
                    "status": "passed",
                    "evidence": validate_result_evidence(
                        {
                            "probe": probe_snapshot["_rawReceipt"],
                            "install": install_binding,
                        },
                        {"probe", "install"},
                        f"target {target['id']} result evidence",
                    ),
                }
            )
            continue

        rollback_output = evidence_dir / f"rollback-{digest}.json"
        rollback_output.unlink(missing_ok=True)
        rollback_result = invoke_driver(
            driver,
            "rollback",
            target_paths[target["id"]],
            rollback_output,
            expectations=expectations,
        )
        rollback_ok = False
        rollback_error = ""
        rollback_binding: dict[str, Any] | None = None
        try:
            if rollback_result.returncode != 0:
                fail(rollback_result.stderr.strip() or "driver rollback failed")
            rollback_evidence = load_driver_evidence(
                rollback_output,
                evidence_dir,
                f"rollback evidence for {target['id']}",
            )
            rollback_binding = dict(rollback_evidence["rawReceipt"])
            validate_rollback(
                rollback_evidence,
                target,
                probe_snapshot,
                transaction_id,
            )
            rollback_ok = True
        except (CanaryError, EvidenceError) as error:
            rollback_error = str(error)
        receipt_bindings = {"probe": probe_snapshot["_rawReceipt"]}
        if install_binding is not None:
            receipt_bindings["install"] = install_binding
        if rollback_binding is not None:
            receipt_bindings["rollback"] = rollback_binding
        report_targets.append(
            {
                "id": target["id"],
                "status": ("failed-rolled-back" if rollback_ok else "failed-rollback"),
                "installError": install_error,
                "rollbackError": rollback_error,
                "evidence": validate_result_evidence(
                    receipt_bindings,
                    set(receipt_bindings),
                    f"target {target['id']} result evidence",
                ),
            }
        )
        rollout_failed = True

    skipped = any(target["status"].startswith("skipped-") for target in report_targets)
    if rollout_failed:
        overall = "failed"
        exit_code = 1
    elif skipped:
        overall = "incomplete"
        exit_code = 2
    else:
        overall = "passed"
        exit_code = 0
    write_json(
        evidence_dir / "fleet-canary-result.json",
        {
            "schema": 2,
            "mode": "execute",
            "status": overall,
            "manifestSha256": manifest_hash,
            "inventorySha256": inventory_hash,
            "driverSha256": driver_hash,
            "releaseGateManifestSha256": release_gate_manifest_hash,
            **source,
            "targets": report_targets,
        },
    )
    print(f"fleet canary {overall}: {len(report_targets)} target(s)")
    return exit_code


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("plan", "execute"))
    parser.add_argument("--root", type=pathlib.Path, required=True)
    parser.add_argument("--fips-root", type=pathlib.Path, required=True)
    parser.add_argument("--inventory", type=pathlib.Path, required=True)
    parser.add_argument("--manifest", type=pathlib.Path, required=True)
    parser.add_argument("--evidence-dir", type=pathlib.Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        if args.mode == "plan":
            return plan(args)
        return execute(args)
    except (CanaryError, EvidenceError) as error:
        print(f"fleet canary blocked: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
