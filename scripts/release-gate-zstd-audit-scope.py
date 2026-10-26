#!/usr/bin/env python3
"""Fail closed when the reviewed 4.1.19 native Zstd audit scope changes."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parent.parent
LOCKS = {
    "Cargo.lock": "c8b636ad8bb42383d87c278ff8b4029b514696adf96519be9416af47e7e806c8",
    "linux/Cargo.lock": "32946f4e8ed169551eec58301524ccb4aafefd847291d970468caf65d6287a48",
}
# The lock hashes also pin the reviewed registry archive checksums. No other
# consumer may gain access to the low-level context/dictionary/buffer APIs.
PACKAGES = {
    "zstd": ("0.13.3", [], {"compression-codecs"}),
    "zstd-safe": ("7.2.4", ["std"], {"compression-codecs", "zstd"}),
    "zstd-sys": ("2.0.16+zstd.1.5.7", ["std"], {"zstd-safe"}),
    "compression-codecs": ("0.4.38", None, {"async-compression"}),
    "compression-core": ("0.4.32", [], {"async-compression", "compression-codecs"}),
    "async-compression": ("0.4.42", ["brotli", "gzip", "tokio", "zlib", "zstd"], {"tower-http"}),
    "tower-http": ("0.6.11", None, {"reqwest", "nostr-vpn-web"}),
}


def require(condition, message):
    if not condition:
        raise ValueError("Zstd audit scope requires review: " + message)


def validate_graph(metadata):
    packages = {p["id"]: p for p in metadata["packages"]}
    nodes = {n["id"]: n for n in metadata["resolve"]["nodes"]}
    result = {}
    for name, (version, features, allowed_parents) in PACKAGES.items():
        matches = [p for p in packages.values() if p["name"] == name]
        require(len(matches) == 1, name + " is missing or duplicated")
        package = matches[0]
        require(package["version"] == version, name + " version changed")
        require(str(package.get("source", "")).startswith("registry+"), name + " source changed")
        node = nodes[package["id"]]
        actual_features = sorted(node["features"])
        if features is not None:
            require(actual_features == features, name + " features changed")
        if name == "tower-http":
            require(not any(f.startswith("compression-") for f in actual_features),
                    "HTTP compression is outside the reviewed decompression path")
        parents = {packages[n["id"]]["name"] for n in nodes.values()
                   if package["id"] in n["dependencies"]}
        require(bool(parents) and parents <= allowed_parents, name + " consumers changed")
        result[name] = {"version": version, "features": actual_features, "parents": sorted(parents)}
    return result


def validate_environment(environment):
    # Presence alone enables zstd-sys system-library mode, including an empty value.
    require("ZSTD_SYS_USE_PKG_CONFIG" not in environment, "system zstd override is present")
    require("wasm" not in environment.get("CARGO_BUILD_TARGET", ""), "WebAssembly is not reviewed")
    for key, value in environment.items():
        if "CFLAGS" in key or "CPPFLAGS" in key:
            require(not value.strip() or value.strip() == "-mno-outline-atomics",
                    "native compiler flag override is present: " + key)
        if key in {"RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS"}:
            require(not value.strip(), "native link/build flag override is present: " + key)


def main():
    require(re.search(r'\[workspace\.package\]\s+version = "4\.1\.19"',
                      (ROOT / "Cargo.toml").read_text()),
            "exception is limited to release 4.1.19; upgrade dependencies before carrying it forward")
    validate_environment(os.environ)
    evidence = {}
    for relative, expected in LOCKS.items():
        lock = ROOT / relative
        require(hashlib.sha256(lock.read_bytes()).hexdigest() == expected, relative + " changed")
        command = ["cargo", "metadata", "--locked", "--format-version", "1",
                   "--manifest-path", str(lock.with_name("Cargo.toml"))]
        metadata = json.loads(subprocess.check_output(command, cwd=ROOT, text=True))
        evidence[relative] = {"sha256": expected, "graph": validate_graph(metadata)}
    print(json.dumps({"scope": "4.1.19-native-bundled-zstd-decompression", "locks": evidence}, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, OSError, subprocess.CalledProcessError) as error:
        raise SystemExit(str(error))
