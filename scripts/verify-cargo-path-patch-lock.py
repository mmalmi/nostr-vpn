#!/usr/bin/env python3
"""Validate the only lockfile delta allowed for exact local FIPS patches."""

from __future__ import annotations

import hashlib
import os
import pathlib
import re
import sys


REGISTRY_SOURCE = (
    'source = "registry+https://github.com/rust-lang/crates.io-index"'
)
PACKAGE_HEADER = "[[package]]"
NAME_RE = re.compile(r'^name = "([^"]+)"$')
VERSION_RE = re.compile(r'^version = "([^"]+)"$')
CHECKSUM_RE = re.compile(r'^checksum = "[0-9a-f]{64}"$')
PATCH_CRATES = {
    "nvpn-fips-core": "fips-core",
    "nvpn-fips-endpoint": "fips-endpoint",
    "nvpn-fips-identity": "fips-identity",
}


def fail(message: str) -> "NoReturn":
    raise SystemExit(f"exact FIPS patched lock verification failed: {message}")


def package_specs(arguments: list[str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for argument in arguments:
        name, separator, version = argument.partition("=")
        if (
            separator != "="
            or not name
            or not re.fullmatch(r"[0-9A-Za-z_.+-]+", name)
            or not re.fullmatch(r"[0-9A-Za-z_.+-]+", version)
            or name in result
        ):
            fail(f"invalid or duplicate package specification: {argument}")
        result[name] = version
    if set(result) != set(PATCH_CRATES):
        fail("package specifications differ from the exact FIPS patch set")
    return result


def manifest_specs(root_arg: str) -> dict[str, str]:
    root = pathlib.Path(root_arg)
    result: dict[str, str] = {}
    for package_name, crate_dir in PATCH_CRATES.items():
        manifest = root / "crates" / crate_dir / "Cargo.toml"
        try:
            text = manifest.read_text(encoding="utf-8")
        except OSError as error:
            fail(f"could not read exact package metadata from {manifest}: {error}")
        match = re.search(
            r'(?ms)^\[package\]\s*$'
            r'(.*?)'
            r'(?=^\[[^\n]+\]\s*$|\Z)',
            text,
        )
        if match is None:
            fail(f"manifest lacks a package table: {manifest}")
        package_text = match.group(1)
        names = re.findall(r'(?m)^name = "([^"]+)"\s*$', package_text)
        versions = re.findall(
            r'(?m)^version = "([^"]+)"\s*$', package_text
        )
        if len(names) != 1 or len(versions) != 1:
            fail(f"manifest lacks one exact package identity: {manifest}")
        name, version = names[0], versions[0]
        if name != package_name or not version:
            fail(f"manifest package identity differs for {package_name}")
        result[name] = version
    return result


def expected_realized_lock(
    committed: bytes, expected_packages: dict[str, str]
) -> bytes:
    try:
        text = committed.decode("utf-8")
    except UnicodeDecodeError as error:
        fail(f"committed lock is not UTF-8: {error}")
    if "\r" in text:
        fail("committed lock has non-canonical line endings")
    lines = text.splitlines(keepends=True)
    if not lines or any(not line.endswith("\n") for line in lines):
        fail("committed lock must be non-empty and newline-terminated")

    starts = [
        index
        for index, line in enumerate(lines)
        if line.removesuffix("\n") == PACKAGE_HEADER
    ]
    starts.append(len(lines))
    removals: set[int] = set()
    found: set[str] = set()
    seen_names: set[str] = set()

    for block_index in range(len(starts) - 1):
        start, end = starts[block_index], starts[block_index + 1]
        block = [line.removesuffix("\n") for line in lines[start:end]]
        names = [
            match.group(1)
            for line in block
            if (match := NAME_RE.fullmatch(line)) is not None
        ]
        versions = [
            match.group(1)
            for line in block
            if (match := VERSION_RE.fullmatch(line)) is not None
        ]
        if len(names) != 1 or len(versions) != 1:
            continue
        name, version = names[0], versions[0]
        if name not in expected_packages:
            continue
        if name in seen_names:
            fail(f"committed lock has duplicate target package: {name}")
        seen_names.add(name)
        if version != expected_packages[name]:
            fail(
                f"committed lock has {name} {version}, "
                f"expected {expected_packages[name]}"
            )

        source_indexes = [
            start + offset
            for offset, line in enumerate(block)
            if line.startswith("source = ")
        ]
        checksum_indexes = [
            start + offset
            for offset, line in enumerate(block)
            if line.startswith("checksum = ")
        ]
        if len(source_indexes) != 1 or len(checksum_indexes) != 1:
            fail(f"committed lock lacks one registry source/checksum for {name}")
        source_index = source_indexes[0]
        checksum_index = checksum_indexes[0]
        if lines[source_index].removesuffix("\n") != REGISTRY_SOURCE:
            fail(f"committed lock has a non-crates.io source for {name}")
        if CHECKSUM_RE.fullmatch(
            lines[checksum_index].removesuffix("\n")
        ) is None:
            fail(f"committed lock has an invalid checksum for {name}")
        removals.update((source_index, checksum_index))
        found.add(name)

    missing = set(expected_packages) - found
    if missing:
        fail(f"committed lock lacks exact target packages: {sorted(missing)}")
    if len(removals) != 2 * len(expected_packages):
        fail("internal target source/checksum count differs")
    return "".join(
        line for index, line in enumerate(lines) if index not in removals
    ).encode("utf-8")


def main() -> None:
    if len(sys.argv) == 3 and sys.argv[1] == "--manifest-specs":
        for name, version in manifest_specs(sys.argv[2]).items():
            print(f"{name}={version}")
        return
    if len(sys.argv) < 4 or sys.argv[1] not in {
        "--expected-sha256",
        "--materialize",
        "--validate",
    }:
        fail(
            "usage: verify-cargo-path-patch-lock.py "
            "--manifest-specs FIPS_ROOT | "
            "--expected-sha256 COMMITTED_LOCK NAME=VERSION [...] | "
            "--materialize COMMITTED_LOCK OUTPUT NAME=VERSION [...] | "
            "--validate COMMITTED_LOCK REALIZED_LOCK NAME=VERSION [...]"
        )
    mode = sys.argv[1]
    if mode == "--expected-sha256":
        committed_arg = sys.argv[2]
        realized_arg = None
        output_arg = None
        specs = sys.argv[3:]
    elif mode == "--materialize":
        if len(sys.argv) < 5:
            fail("materialize mode requires committed and output locks")
        committed_arg = sys.argv[2]
        realized_arg = None
        output_arg = sys.argv[3]
        specs = sys.argv[4:]
    else:
        if len(sys.argv) < 5:
            fail("validate mode requires committed and realized locks")
        committed_arg = sys.argv[2]
        realized_arg = sys.argv[3]
        output_arg = None
        specs = sys.argv[4:]

    try:
        committed = pathlib.Path(committed_arg).read_bytes()
    except OSError as error:
        fail(f"could not read committed lock: {error}")
    expected = expected_realized_lock(committed, package_specs(specs))
    if realized_arg is not None:
        try:
            realized = pathlib.Path(realized_arg).read_bytes()
        except OSError as error:
            fail(f"could not read realized lock: {error}")
        if realized != expected:
            fail(
                "realized lock differs by more than exact target "
                "source/checksum removal"
            )
    if output_arg is not None:
        output = pathlib.Path(output_arg)
        try:
            descriptor = os.open(
                output,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o400,
            )
        except OSError as error:
            fail(f"could not create materialized lock output: {error}")
        with os.fdopen(descriptor, "wb") as destination:
            destination.write(expected)
            destination.flush()
            os.fsync(destination.fileno())
    print(hashlib.sha256(expected).hexdigest())


if __name__ == "__main__":
    main()
