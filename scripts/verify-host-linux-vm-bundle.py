#!/usr/bin/env python3
"""Verify the immutable exact bundle imported by Ubuntu VM gates."""

from __future__ import annotations

import hashlib
import json
import pathlib
import re
import stat
import sys

from host_linux_package_content import (
    PackageVerificationError,
    verify_debian_package,
    verify_musl_archive,
)


def fail(message: str) -> "NoReturn":
    raise SystemExit(f"host Linux VM bundle verification failed: {message}")


def sha256_path(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as artifact:
        for chunk in iter(lambda: artifact.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


if len(sys.argv) != 21:
    fail(
        "usage: verify-host-linux-vm-bundle.py "
        "BUNDLE RECEIPT APP_SHA APP_TREE APP_VERSION "
        "FIPS_SHA FIPS_TREE FIPS_VERSION "
        "ROOT_CARGO_LOCK_SHA256 ROOT_REALIZED_CARGO_LOCK_SHA256 "
        "LINUX_CARGO_LOCK_SHA256 LINUX_REALIZED_CARGO_LOCK_SHA256 TARGET "
        "BUILDER_MODE RUST_TOOLCHAIN DOCKERFILE_SHA256 PAYLOAD_SHA256 "
        "FIPS_CORE_SPEC FIPS_ENDPOINT_SPEC FIPS_IDENTITY_SPEC"
    )

(
    bundle_arg,
    receipt_arg,
    app_sha,
    app_tree,
    app_version,
    fips_sha,
    fips_tree,
    fips_version,
    root_cargo_lock_sha256,
    root_realized_cargo_lock_sha256,
    linux_cargo_lock_sha256,
    linux_realized_cargo_lock_sha256,
    target,
    builder_mode,
    rust_toolchain,
    dockerfile_sha256,
    container_payload_sha256,
    fips_core_patch_spec,
    fips_endpoint_patch_spec,
    fips_identity_patch_spec,
) = sys.argv[1:]
bundle = pathlib.Path(bundle_arg)
receipt_path = pathlib.Path(receipt_arg)

if not bundle.is_dir() or bundle.is_symlink():
    fail("bundle path is not a real directory")
if receipt_path.parent.resolve() != bundle.resolve():
    fail("receipt is not inside the bundle")
if receipt_path.name != "receipt.json" or receipt_path.is_symlink():
    fail("receipt path is not the exact regular receipt")

try:
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
except (OSError, ValueError) as error:
    fail(f"could not parse receipt: {error}")

for label, value in (
    ("root committed Cargo lock", root_cargo_lock_sha256),
    ("root realized Cargo lock", root_realized_cargo_lock_sha256),
    ("Linux committed Cargo lock", linux_cargo_lock_sha256),
    ("Linux realized Cargo lock", linux_realized_cargo_lock_sha256),
    ("Dockerfile", dockerfile_sha256),
    ("container payload", container_payload_sha256),
):
    if re.fullmatch(r"[0-9a-f]{64}", value) is None:
        fail(f"{label} SHA-256 is invalid")
if re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", rust_toolchain) is None:
    fail("Rust toolchain version is invalid")

fips_patch_packages: dict[str, str] = {}
for specification in (
    fips_core_patch_spec,
    fips_endpoint_patch_spec,
    fips_identity_patch_spec,
):
    name, separator, version = specification.partition("=")
    if (
        separator != "="
        or name in fips_patch_packages
        or re.fullmatch(r"[0-9A-Za-z_.+-]+", version) is None
    ):
        fail("exact FIPS patched lock package specification is invalid")
    fips_patch_packages[name] = version
if set(fips_patch_packages) != {
    "nvpn-fips-core",
    "nvpn-fips-endpoint",
    "nvpn-fips-identity",
}:
    fail("exact FIPS patched lock package set differs")

expected_metadata = {
    "schema": 2,
    "builderMode": builder_mode,
    "appGitSha": app_sha,
    "appGitTree": app_tree,
    "appVersion": app_version,
    "fipsGitSha": fips_sha,
    "fipsGitTree": fips_tree,
    "fipsVersion": fips_version,
    "rootCargoLockSha256": root_cargo_lock_sha256,
    "rootRealizedCargoLockSha256": root_realized_cargo_lock_sha256,
    "linuxCargoLockSha256": linux_cargo_lock_sha256,
    "linuxRealizedCargoLockSha256": linux_realized_cargo_lock_sha256,
    "fipsPatchedLockPackages": fips_patch_packages,
    "target": target,
    "dockerPlatform": "linux/amd64",
    "containerBase": "ubuntu:24.04",
    "dockerfileSha256": dockerfile_sha256,
    "containerPayloadSha256": container_payload_sha256,
}
for key, expected in expected_metadata.items():
    if receipt.get(key) != expected:
        fail(f"receipt {key} differs from the exact candidate")

builder_modes = {
    "local-docker": {
        "builtOnHostMac": True,
        "builtOnRemoteVm": False,
        "builderHostOs": "Darwin",
        "builderHostArchitectures": {"arm64", "x86_64"},
    },
    "remote-native": {
        "builtOnHostMac": False,
        "builtOnRemoteVm": True,
        "builderHostOs": "Linux",
        "builderHostArchitectures": {"x86_64"},
    },
}
if builder_mode not in builder_modes:
    fail("builder mode is not one of the two exact supported modes")
builder = builder_modes[builder_mode]
for key in ("builtOnHostMac", "builtOnRemoteVm", "builderHostOs"):
    if receipt.get(key) != builder[key]:
        fail(f"receipt {key} conflicts with builder mode")
if receipt.get("builderHostArchitecture") not in builder[
    "builderHostArchitectures"
]:
    fail("receipt builder architecture conflicts with builder mode")
if (
    builder_mode == "local-docker"
    and receipt.get("builderHostArchitecture") != "x86_64"
):
    fail("local-docker amd64 release builds require a native x86_64 Mac")
if (
    re.fullmatch(r"sha256:[0-9a-f]{64}", receipt.get("containerImageId", ""))
    is None
):
    fail("receipt container image identity is invalid")

if not isinstance(receipt.get("sourceDateEpoch"), int) or receipt["sourceDateEpoch"] <= 0:
    fail("receipt lacks a positive sourceDateEpoch")
for key in ("rustcVersion", "cargoVersion"):
    if not isinstance(receipt.get(key), str) or not receipt[key].strip():
        fail(f"receipt lacks {key}")
if not receipt["rustcVersion"].startswith(f"rustc {rust_toolchain} "):
    fail("receipt rustc version differs from the pinned toolchain")
if not receipt["cargoVersion"].startswith(f"cargo {rust_toolchain} "):
    fail("receipt cargo version differs from the pinned toolchain")

artifacts = receipt.get("artifacts")
expected_artifacts = {
    "app": "nostr-vpn",
    "cli": "nvpn",
    "manualJoinFixture": "desktop_manual_join_e2e_fixture",
    "muslCli": "nvpn-x86_64-unknown-linux-musl",
    "debianPackage": "nostr-vpn.deb",
    "muslCliArchive": "nvpn-x86_64-unknown-linux-musl.tar.gz",
}
if not isinstance(artifacts, dict) or set(artifacts) != set(expected_artifacts):
    fail("receipt artifact set is not exact")

expected_files = {"receipt.json", *expected_artifacts.values()}
actual_files = {path.name for path in bundle.iterdir()}
if actual_files != expected_files:
    fail(f"bundle file set differs: expected {sorted(expected_files)}, got {sorted(actual_files)}")

executable_labels = {"app", "cli", "manualJoinFixture", "muslCli"}
for label, filename in expected_artifacts.items():
    entry = artifacts.get(label)
    if not isinstance(entry, dict) or entry.get("file") != filename:
        fail(f"{label} receipt has the wrong filename")
    path = bundle / filename
    try:
        metadata = path.lstat()
    except OSError as error:
        fail(f"could not stat {filename}: {error}")
    if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
        fail(f"{filename} is not a regular non-symlink artifact")
    expected_mode = 0o555 if label in executable_labels else 0o444
    if stat.S_IMODE(metadata.st_mode) != expected_mode:
        fail(f"{filename} mode differs from the immutable bundle contract")
    if label in executable_labels:
        with path.open("rb") as artifact:
            header = artifact.read(20)
        if (
            len(header) < 20
            or header[:4] != b"\x7fELF"
            or header[4] != 2
            or header[5] != 1
            or int.from_bytes(header[18:20], "little") != 62
        ):
            fail(f"{filename} is not a little-endian x86_64 ELF64 executable")
    digest = sha256_path(path)
    if entry.get("sha256") != digest:
        fail(f"{filename} SHA-256 differs from receipt")
    if entry.get("size") != metadata.st_size or metadata.st_size <= 0:
        fail(f"{filename} size differs from receipt")

cli_short = receipt.get("cliShortVersion")
cli_verbose = receipt.get("cliVerboseVersion")
if cli_short != f"nvpn {app_version}":
    fail("receipt CLI short version differs from app version")
if not isinstance(cli_verbose, str) or f"(rev {fips_sha[:10]})" not in cli_verbose:
    fail("receipt CLI verbose version differs from exact FIPS revision")

if receipt.get("muslTarget") != "x86_64-unknown-linux-musl":
    fail("receipt lacks the exact static Linux CLI target")
if receipt.get("cargoDebVersion") != "3.7.0":
    fail("receipt lacks the pinned cargo-deb version")
if receipt.get("muslCliShortVersion") != f"nvpn {app_version}":
    fail("receipt static CLI short version differs from app version")
musl_verbose = receipt.get("muslCliVerboseVersion")
if (
    not isinstance(musl_verbose, str)
    or f"(rev {fips_sha[:10]})" not in musl_verbose
):
    fail("receipt static CLI verbose version differs from exact FIPS revision")

package = receipt.get("debianPackage")
if (
    not isinstance(package, dict)
    or package.get("package") != "nostr-vpn"
    or package.get("version") != f"{app_version}-1"
    or package.get("architecture") != "amd64"
    or package.get("appPath") != "usr/bin/nostr-vpn"
    or package.get("cliPath") != "usr/bin/nvpn"
):
    fail("receipt Debian package metadata differs from the candidate")
try:
    repo_root = pathlib.Path(__file__).resolve().parent.parent
    verify_debian_package(
        repo_root=repo_root,
        deb_path=bundle / expected_artifacts["debianPackage"],
        app_version=app_version,
        source_date_epoch=receipt["sourceDateEpoch"],
        app_sha256=artifacts["app"]["sha256"],
        cli_sha256=artifacts["cli"]["sha256"],
    )
    verify_musl_archive(
        archive_path=bundle / expected_artifacts["muslCliArchive"],
        source_date_epoch=receipt["sourceDateEpoch"],
        musl_cli_sha256=artifacts["muslCli"]["sha256"],
    )
except (OSError, PackageVerificationError) as error:
    fail(str(error))

print("HOST_LINUX_VM_BUNDLE_VERIFIED")
