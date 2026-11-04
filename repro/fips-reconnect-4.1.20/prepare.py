#!/usr/bin/env python3
"""Reconstruct and verify the recorded reconnect qualification build context."""

import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import tarfile
import urllib.request


HERE = Path(__file__).resolve().parent
REPOSITORY = HERE.parents[1]


def unpack(archive, destination, prefix=""):
    with tarfile.open(fileobj=io.BytesIO(archive)) as bundle:
        for member in bundle.getmembers():
            name = member.name
            if prefix:
                if not name.startswith(prefix):
                    raise ValueError("Unexpected registry archive prefix")
                name = name[len(prefix):]
            path = PurePosixPath(name)
            if path.is_absolute() or ".." in path.parts:
                raise ValueError("Unsafe source archive path")
            if member.isdir():
                continue
            if not member.isfile():
                raise ValueError("Source archive must contain regular files")
            target = destination / path
            target.parent.mkdir(parents=True, exist_ok=True)
            with bundle.extractfile(member) as source, target.open("xb") as output:
                shutil.copyfileobj(source, output)
            target.chmod(0o600)


def prepare(destination, crate_path):
    inputs = json.loads((HERE / "inputs.json").read_text())
    destination.mkdir(mode=0o700, parents=False, exist_ok=False)
    archive = subprocess.check_output([
        "git", "-C", str(REPOSITORY), "archive", inputs["nvpn_commit"],
        "Cargo.toml", "crates", "vendor", "umbrel/Dockerfile",
    ])
    unpack(archive, destination)
    if crate_path:
        crate = crate_path.read_bytes()
    else:
        with urllib.request.urlopen(inputs["crate_url"], timeout=60) as response:
            crate = response.read()
    if hashlib.sha256(crate).hexdigest() != inputs["original_crate_sha256"]:
        raise ValueError("Registry source checksum mismatch")
    core = destination / "qualified-core"
    unpack(crate, core, "nvpn-fips-core-0.4.115/")
    patch = HERE / "core.patch"
    if hashlib.sha256(patch.read_bytes()).hexdigest() != inputs["production_patch_sha256"]:
        raise ValueError("Reviewed FIPS patch checksum mismatch")
    subprocess.run(["git", "apply", "--no-index", "-p3", str(patch)], cwd=core, check=True)
    with (destination / "Cargo.toml").open("a") as manifest:
        manifest.write('\n[patch.crates-io]\nnvpn-fips-core = { path = "/qualified-core" }\n')
    for name in ("Cargo.lock", "Qualification.Dockerfile", ".dockerignore"):
        shutil.copyfile(HERE / name, destination / name)
    for path in destination.rglob("*"):
        if path.is_file():
            path.chmod(0o600)
    actual = {
        str(path.relative_to(destination)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in destination.rglob("*") if path.is_file()
    }
    if actual != inputs["expected_context_files"]:
        raise ValueError("Reconstructed source differs from the qualified context")
    print(f"Verified {len(actual)} exact source and recipe files")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path, help="New build-context directory")
    parser.add_argument("--crate", type=Path, help="Optional existing registry archive, still checksum-verified")
    options = parser.parse_args()
    os.umask(0o077)
    prepare(options.destination.resolve(), options.crate)
