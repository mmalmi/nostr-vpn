#!/usr/bin/env bash
# Executable contracts for exact/import-only native Linux VM bundles.
# shellcheck disable=SC2034 # Fixture variables are read by sourced builder helpers.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERIFIER="$ROOT/scripts/verify-host-linux-vm-bundle.py"
PATCH_LOCK_VERIFIER="$ROOT/scripts/verify-cargo-path-patch-lock.py"
CLEANUP_HARNESS="$ROOT/scripts/test-ubuntu-vm-exact-deb-cleanup-harness.sh"
RECOVERY_HARNESS="$ROOT/scripts/test-ubuntu-vm-stale-import-recovery-harness.sh"
JOIN_SERVICE_CLEANUP_HARNESS="$ROOT/scripts/test-linux-release-mobile-join-service-cleanup-harness.sh"
IMPORT_ENV_ISOLATION_HARNESS="$ROOT/scripts/test-ubuntu-vm-import-env-isolation-harness.sh"
ISOLATION_HARNESS="$ROOT/scripts/test-host-linux-builder-isolation-harness.sh"
NATIVE_BUILDER_LIB="$ROOT/scripts/lib-host-linux-native-builder.sh"
CARGO_CACHE_VERIFIER="$ROOT/scripts/host_linux_cargo_archive_cache.py"
SOURCE_AUDITOR="$ROOT/scripts/verify_host_linux_build_source.py"

fail() {
  echo "host Linux VM import-only contract failed: $*" >&2
  exit 1
}

for executable in \
  "$VERIFIER" \
  "$PATCH_LOCK_VERIFIER" \
  "$CLEANUP_HARNESS" \
  "$RECOVERY_HARNESS" \
  "$JOIN_SERVICE_CLEANUP_HARNESS" \
  "$IMPORT_ENV_ISOLATION_HARNESS" \
  "$ISOLATION_HARNESS" \
  "$CARGO_CACHE_VERIFIER" \
  "$SOURCE_AUDITOR"
do
  [[ -x "$executable" ]] || fail "$(basename "$executable") is not executable"
done
[[ -f "$NATIVE_BUILDER_LIB" ]] \
  || fail "native Linux builder helper is missing"

"$ISOLATION_HARNESS"
"$CLEANUP_HARNESS"
"$RECOVERY_HARNESS"
"$IMPORT_ENV_ISOLATION_HARNESS"
"$JOIN_SERVICE_CLEANUP_HARNESS"

tmp="$(mktemp -d "${TMPDIR:-/tmp}/nvpn-host-linux-bundle-contract.XXXXXX")"
backup="$(mktemp -d "${TMPDIR:-/tmp}/nvpn-host-linux-bundle-backup.XXXXXX")"
trap 'rm -rf "$tmp" "$backup"' EXIT
app_sha="$(printf 'a%.0s' {1..40})"
app_tree="$(printf 'b%.0s' {1..40})"
fips_sha="$(printf 'c%.0s' {1..40})"
fips_tree="$(printf 'd%.0s' {1..40})"
root_lock_sha="$(printf 'e%.0s' {1..64})"
linux_lock_sha="$(printf 'f%.0s' {1..64})"
root_realized_lock_sha="$(printf '1%.0s' {1..64})"
linux_realized_lock_sha="$(printf '2%.0s' {1..64})"
dockerfile_sha="$(printf '3%.0s' {1..64})"
payload_sha="$(printf '4%.0s' {1..64})"
container_image_id="sha256:$(printf '5%.0s' {1..64})"
rust_toolchain="1.95.0"
app_version="4.1.5"
fips_version="0.4.45"

safe_tar="$backup/native-output-safe.tar"
unsafe_tar="$backup/native-output-traversal.tar"
python3 - "$safe_tar" "$unsafe_tar" <<'PY'
import io
import sys
import tarfile

expected = (
    "builder-provenance.json",
    "cargo-version.txt",
    "cli-short-version.txt",
    "cli-verbose-version.txt",
    "deb-version.txt",
    "desktop_manual_join_e2e_fixture",
    "file.txt",
    "linux-Cargo.lock.committed",
    "linux-realized-cargo-lock-sha256.txt",
    "musl-cli-short-version.txt",
    "musl-cli-verbose-version.txt",
    "nostr-vpn",
    "nostr-vpn.deb",
    "nvpn",
    "nvpn-x86_64-unknown-linux-musl",
    "nvpn-x86_64-unknown-linux-musl.tar.gz",
    "root-Cargo.lock.committed",
    "root-realized-cargo-lock-sha256.txt",
    "rustc-version.txt",
)
with tarfile.open(sys.argv[1], "w:") as archive:
    for name in expected:
        raw = f"{name}\n".encode()
        info = tarfile.TarInfo(name)
        info.size = len(raw)
        archive.addfile(info, io.BytesIO(raw))
with tarfile.open(sys.argv[2], "w:") as archive:
    raw = b"escape\n"
    info = tarfile.TarInfo("../builder-provenance.json")
    info.size = len(raw)
    archive.addfile(info, io.BytesIO(raw))
PY
# shellcheck disable=SC1090
source "$NATIVE_BUILDER_LIB"
NVPN_HOST_LINUX_VM_NATIVE_BUILDER_HOST="release-builder"
NVPN_HOST_LINUX_VM_NATIVE_BUILDER_JUMP=""
NVPN_HOST_LINUX_VM_NATIVE_BUILDER_PROXY_COMMAND=""
host_linux_native_builder_commands \
  || fail "native builder rejected a location-neutral SSH alias"
NVPN_HOST_LINUX_VM_NATIVE_BUILDER_HOST="2001:db8::1"
if host_linux_native_builder_commands >/dev/null 2>&1; then
  fail "native builder accepted an ambiguous SCP IPv6 destination"
fi
NVPN_HOST_LINUX_VM_NATIVE_BUILDER_HOST="release-builder"
NVPN_HOST_LINUX_VM_NATIVE_BUILDER_JUMP="ssh-jump"
NVPN_HOST_LINUX_VM_NATIVE_BUILDER_PROXY_COMMAND="ssh -W %h:%p ssh-jump"
if host_linux_native_builder_commands >/dev/null 2>&1; then
  fail "native builder accepted both jump and proxy transports"
fi
NVPN_HOST_LINUX_VM_NATIVE_BUILDER_JUMP=""
NVPN_HOST_LINUX_VM_NATIVE_BUILDER_PROXY_COMMAND=""
NVPN_HOST_LINUX_NATIVE_REMOTE_DIR="/tmp/nvpn-linux-native-builder.abc123/escape"
if host_linux_native_builder_cleanup_remote >/dev/null 2>&1; then
  fail "native builder accepted an unsafe remote cleanup path"
fi
NVPN_HOST_LINUX_NATIVE_REMOTE_DIR=""
mkdir "$backup/native-output-safe"
host_linux_native_builder_extract_output \
  "$safe_tar" "$backup/native-output-safe"
[[ "$(find "$backup/native-output-safe" -type f | wc -l | tr -d ' ')" == 19 ]] \
  || fail "safe native output import did not preserve the exact member set"
mkdir "$backup/native-output-traversal"
if host_linux_native_builder_extract_output \
  "$unsafe_tar" "$backup/native-output-traversal" >/dev/null 2>&1
then
  fail "native output import accepted a traversal member"
fi
mkdir "$backup/native-output-symlink"
ln -s "$backup/escape-target" \
  "$backup/native-output-symlink/builder-provenance.json"
if host_linux_native_builder_extract_output \
  "$safe_tar" "$backup/native-output-symlink" >/dev/null 2>&1
then
  fail "native output import followed a preexisting destination symlink"
fi

lock_test="$backup/lock-adversary"
mkdir -p "$lock_test"
python3 - "$lock_test" <<'PY'
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
source = 'source = "registry+https://github.com/rust-lang/crates.io-index"\n'


def package(name: str, version: str, checksum: str, patched: bool) -> str:
    result = f'[[package]]\nname = "{name}"\nversion = "{version}"\n'
    if not patched:
        result += source + f'checksum = "{checksum}"\n'
    return result + 'dependencies = ["stable"]\n\n'


targets = (
    ("nvpn-fips-core", "0.4.65", "a" * 64),
    ("nvpn-fips-endpoint", "0.4.65", "b" * 64),
    ("nvpn-fips-identity", "0.3.3", "c" * 64),
)
unrelated = ("unrelated", "1.0.0", "d" * 64)
prefix = "version = 4\n\n"
committed = prefix + "".join(
    package(name, version, checksum, False)
    for name, version, checksum in (*targets, unrelated)
)
realized = prefix + "".join(
    package(name, version, checksum, True)
    for name, version, checksum in targets
) + package(*unrelated, False)
partial = prefix + package(*targets[0], True) + "".join(
    package(name, version, checksum, False)
    for name, version, checksum in (*targets[1:], unrelated)
)
extra = realized.replace(source, "", 1)
dependency = realized.replace(
    'dependencies = ["stable"]', 'dependencies = ["changed"]', 1
)
version = realized.replace(
    'name = "nvpn-fips-identity"\nversion = "0.3.3"',
    'name = "nvpn-fips-identity"\nversion = "0.3.4"',
)
wrong_version = committed.replace(
    'name = "nvpn-fips-identity"\nversion = "0.3.3"',
    'name = "nvpn-fips-identity"\nversion = "0.3.4"',
)
for name, value in (
    ("committed.lock", committed),
    ("realized.lock", realized),
    ("partial.lock", partial),
    ("extra.lock", extra),
    ("dependency.lock", dependency),
    ("version.lock", version),
    ("wrong-version.lock", wrong_version),
):
    (root / name).write_text(value, encoding="utf-8")
PY
patch_specs=(
  nvpn-fips-core=0.4.65
  nvpn-fips-endpoint=0.4.65
  nvpn-fips-identity=0.3.3
)
expected_patch_sha="$(
  python3 "$PATCH_LOCK_VERIFIER" \
    --expected-sha256 "$lock_test/committed.lock" "${patch_specs[@]}"
)"
[[ "$(
  python3 "$PATCH_LOCK_VERIFIER" \
    --validate "$lock_test/committed.lock" "$lock_test/realized.lock" \
    "${patch_specs[@]}"
)" == "$expected_patch_sha" ]] \
  || fail "exact FIPS patch lock verifier rejected the canonical delta"
python3 "$PATCH_LOCK_VERIFIER" \
  --materialize "$lock_test/committed.lock" \
  "$lock_test/materialized.lock" "${patch_specs[@]}" >/dev/null
cmp -s "$lock_test/materialized.lock" "$lock_test/realized.lock" \
  || fail "exact FIPS patch lock materialization changed canonical bytes"
if python3 "$PATCH_LOCK_VERIFIER" \
  --materialize "$lock_test/committed.lock" \
  "$lock_test/materialized.lock" "${patch_specs[@]}" >/dev/null 2>&1
then
  fail "exact FIPS patch lock materialization replaced an existing output"
fi
for adversary in partial.lock extra.lock dependency.lock version.lock; do
  if python3 "$PATCH_LOCK_VERIFIER" \
    --validate "$lock_test/committed.lock" "$lock_test/$adversary" \
    "${patch_specs[@]}" >/dev/null 2>&1
  then
    fail "exact FIPS patch lock verifier accepted $adversary"
  fi
done
if python3 "$PATCH_LOCK_VERIFIER" \
  --expected-sha256 "$lock_test/wrong-version.lock" "${patch_specs[@]}" \
  >/dev/null 2>&1
then
  fail "exact FIPS patch lock verifier accepted the wrong package version"
fi

cargo_cache_test="$backup/cargo-cache-adversary"
mkdir -p \
  "$cargo_cache_test/cache-parent" \
  "$cargo_cache_test/home/registry/cache/index.crates.io-1949cf8c6b5b557f"
printf 'exact crate archive\n' >"$cargo_cache_test/exact-1.0.0.crate"
cargo_cache_checksum="$(
  shasum -a 256 "$cargo_cache_test/exact-1.0.0.crate" | awk '{print $1}'
)"
cat >"$cargo_cache_test/Cargo.lock" <<EOF
version = 4

[[package]]
name = "exact"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "$cargo_cache_checksum"
EOF
cp "$cargo_cache_test/exact-1.0.0.crate" \
  "$cargo_cache_test/home/registry/cache/index.crates.io-1949cf8c6b5b557f/"
mkdir -p \
  "$cargo_cache_test/home/registry/src/index.crates.io-1949cf8c6b5b557f/exact-1.0.0"
printf 'Cargo 1.95 extracted source without a legacy checksum manifest\n' \
  >"$cargo_cache_test/home/registry/src/index.crates.io-1949cf8c6b5b557f/exact-1.0.0/lib.rs"
python3 "$CARGO_CACHE_VERIFIER" store \
  "$cargo_cache_test/cache-parent/exact" \
  "$cargo_cache_test/home" \
  "$cargo_cache_test/Cargo.lock" "$cargo_cache_test/Cargo.lock"
[[ ! -e "$cargo_cache_test/home/registry/src" \
  && ! -L "$cargo_cache_test/home/registry/src" ]] \
  || fail "Cargo download cache retained realized registry sources"
cache_manifest="$cargo_cache_test/cache-parent/exact/manifest.json"
cache_manifest_real="$cargo_cache_test/cache-parent/manifest.json.real"
mv "$cache_manifest" "$cache_manifest_real"
ln -s ../manifest.json.real "$cache_manifest"
mkdir "$cargo_cache_test/symlinked-manifest-seed"
if python3 "$CARGO_CACHE_VERIFIER" seed \
  "$cargo_cache_test/cache-parent/exact" \
  "$cargo_cache_test/symlinked-manifest-seed" \
  "$cargo_cache_test/Cargo.lock" "$cargo_cache_test/Cargo.lock" \
  >/dev/null 2>&1
then
  fail "Cargo download cache accepted a symlinked manifest"
fi
unlink "$cache_manifest"
mv "$cache_manifest_real" "$cache_manifest"
mkdir "$cargo_cache_test/seeded"
python3 "$CARGO_CACHE_VERIFIER" seed \
  "$cargo_cache_test/cache-parent/exact" \
  "$cargo_cache_test/seeded" \
  "$cargo_cache_test/Cargo.lock" "$cargo_cache_test/Cargo.lock"
printf '[build]\nrustc-wrapper = "/tmp/forged-wrapper"\n' \
  >"$cargo_cache_test/seeded/config.toml"
if python3 "$CARGO_CACHE_VERIFIER" audit \
  "$cargo_cache_test/cache-parent/exact" \
  "$cargo_cache_test/seeded" \
  "$cargo_cache_test/Cargo.lock" "$cargo_cache_test/Cargo.lock" \
  >/dev/null 2>&1
then
  fail "fresh Cargo home accepted an injected config.toml surface"
fi
unlink "$cargo_cache_test/seeded/config.toml"
cache_archive="$cargo_cache_test/cache-parent/exact/exact-1.0.0.crate"
chmod u+w "$cache_archive"
printf 'forged crate archive\n' >"$cache_archive"
chmod 0444 "$cache_archive"
mkdir "$cargo_cache_test/forged-seed"
if python3 "$CARGO_CACHE_VERIFIER" seed \
  "$cargo_cache_test/cache-parent/exact" \
  "$cargo_cache_test/forged-seed" \
  "$cargo_cache_test/Cargo.lock" "$cargo_cache_test/Cargo.lock" \
  >/dev/null 2>&1
then
  fail "Cargo download cache accepted forged archive bytes"
fi

source_audit_test="$backup/source-audit-adversary"
mkdir -p "$source_audit_test/pristine/linux"
git -C "$source_audit_test/pristine" init -q
printf 'committed root\n' >"$source_audit_test/pristine/Cargo.lock"
printf 'committed linux\n' >"$source_audit_test/pristine/linux/Cargo.lock"
printf 'exact source\n' >"$source_audit_test/pristine/source.txt"
printf '*.ignored\n' >"$source_audit_test/pristine/.gitignore"
git -C "$source_audit_test/pristine" add \
  .gitignore Cargo.lock linux/Cargo.lock source.txt
git -C "$source_audit_test/pristine" \
  -c user.name=test -c user.email=test@example.invalid \
  commit -qm exact
git clone -q "$source_audit_test/pristine" "$source_audit_test/build"
find "$source_audit_test/pristine" "$source_audit_test/build" \
  -type d -exec chmod 0755 {} +
find "$source_audit_test/pristine" "$source_audit_test/build" \
  -path '*/.git' -prune -o -type f -exec chmod 0644 {} +
printf 'realized root\n' >"$source_audit_test/build/Cargo.lock"
printf 'realized linux\n' >"$source_audit_test/build/linux/Cargo.lock"
source_audit_sha="$(git -C "$source_audit_test/pristine" rev-parse HEAD)"
source_audit_tree="$(
  git -C "$source_audit_test/pristine" rev-parse 'HEAD^{tree}'
)"
source_audit_root_lock="$(
  shasum -a 256 "$source_audit_test/build/Cargo.lock" | awk '{print $1}'
)"
source_audit_linux_lock="$(
  shasum -a 256 "$source_audit_test/build/linux/Cargo.lock" | awk '{print $1}'
)"
python3 "$SOURCE_AUDITOR" \
  "$source_audit_test/pristine" "$source_audit_test/build" \
  "$source_audit_sha" "$source_audit_tree" \
  "$source_audit_root_lock" "$source_audit_linux_lock" >/dev/null
printf 'ignored source injection\n' \
  >"$source_audit_test/pristine/injected.ignored"
printf 'ignored source injection\n' \
  >"$source_audit_test/build/injected.ignored"
if python3 "$SOURCE_AUDITOR" \
  "$source_audit_test/pristine" "$source_audit_test/build" \
  "$source_audit_sha" "$source_audit_tree" \
  "$source_audit_root_lock" "$source_audit_linux_lock" \
  >/dev/null 2>&1
then
  fail "post-build source audit accepted identical ignored source injection"
fi
rm \
  "$source_audit_test/pristine/injected.ignored" \
  "$source_audit_test/build/injected.ignored"
for checkout in pristine build; do
  git -C "$source_audit_test/$checkout" \
    update-index --assume-unchanged source.txt
  printf 'status-hidden source injection\n' \
    >"$source_audit_test/$checkout/source.txt"
done
[[ -z "$(git -C "$source_audit_test/pristine" \
  status --porcelain --untracked-files=all)" ]]
if python3 "$SOURCE_AUDITOR" \
  "$source_audit_test/pristine" "$source_audit_test/build" \
  "$source_audit_sha" "$source_audit_tree" \
  "$source_audit_root_lock" "$source_audit_linux_lock" \
  >/dev/null 2>&1
then
  fail "post-build source audit trusted status-hidden transformed source"
fi
for checkout in pristine build; do
  git -C "$source_audit_test/$checkout" \
    update-index --no-assume-unchanged source.txt
  git -C "$source_audit_test/$checkout" checkout -- source.txt
done
printf 'forged output\n' >"$source_audit_test/build/target-forged"
if python3 "$SOURCE_AUDITOR" \
  "$source_audit_test/pristine" "$source_audit_test/build" \
  "$source_audit_sha" "$source_audit_tree" \
  "$source_audit_root_lock" "$source_audit_linux_lock" \
  >/dev/null 2>&1
then
  fail "post-build source audit accepted a forged untracked output"
fi

python3 - \
  "$tmp" "$ROOT" "$app_sha" "$app_tree" "$app_version" \
  "$fips_sha" "$fips_tree" "$fips_version" \
  "$root_lock_sha" "$root_realized_lock_sha" \
  "$linux_lock_sha" "$linux_realized_lock_sha" \
  "$dockerfile_sha" "$payload_sha" "$container_image_id" \
  "$rust_toolchain" \
  "${patch_specs[@]}" <<'PY'
import hashlib
import io
import json
import os
import pathlib
import sys
import tarfile

root = pathlib.Path(sys.argv[1])
repo_root = pathlib.Path(sys.argv[2])
(
    app_sha,
    app_tree,
    app_version,
    fips_sha,
    fips_tree,
    fips_version,
    root_lock_sha,
    root_realized_lock_sha,
    linux_lock_sha,
    linux_realized_lock_sha,
    dockerfile_sha,
    payload_sha,
    container_image_id,
    rust_toolchain,
    fips_core_patch_spec,
    fips_endpoint_patch_spec,
    fips_identity_patch_spec,
) = sys.argv[3:]
fips_patch_packages = dict(
    spec.split("=", 1)
    for spec in (
        fips_core_patch_spec,
        fips_endpoint_patch_spec,
        fips_identity_patch_spec,
    )
)
executables = {
    "app": "nostr-vpn",
    "cli": "nvpn",
    "manualJoinFixture": "desktop_manual_join_e2e_fixture",
    "muslCli": "nvpn-x86_64-unknown-linux-musl",
}
artifacts = {}
for index, (label, name) in enumerate(executables.items(), start=1):
    raw = bytearray(64)
    raw[:6] = b"\x7fELF\x02\x01"
    raw[18:20] = (62).to_bytes(2, "little")
    raw[32] = index
    path = root / name
    path.write_bytes(raw)
    path.chmod(0o555)
    artifacts[label] = {
        "file": name,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "size": len(raw),
    }
archive_path = root / "nvpn-x86_64-unknown-linux-musl.tar.gz"
with tarfile.open(
    archive_path, "w:gz", format=tarfile.USTAR_FORMAT
) as archive:
    for name, raw, mode in (
        ("nvpn/README.txt", b"nvpn - FIPS private mesh CLI\n", 0o644),
        (
            "nvpn/install.sh",
            b"#!/bin/bash\n"
            b"set -e\n"
            b'install -d "${1:-/usr/local/bin}"\n'
            b'install -m 755 nvpn "${1:-/usr/local/bin}/"\n',
            0o555,
        ),
        (
            "nvpn/nvpn",
            (root / executables["muslCli"]).read_bytes(),
            0o555,
        ),
    ):
        info = tarfile.TarInfo(name)
        info.size = len(raw)
        info.mode = mode
        info.mtime = 1
        info.uid = 0
        info.gid = 0
        info.uname = ""
        info.gname = ""
        archive.addfile(info, io.BytesIO(raw))
archive_path.chmod(0o444)
artifacts["muslCliArchive"] = {
    "file": archive_path.name,
    "sha256": hashlib.sha256(archive_path.read_bytes()).hexdigest(),
    "size": archive_path.stat().st_size,
}

data_files = {
    "./usr/bin/nostr-vpn": (
        (root / executables["app"]).read_bytes(),
        0o755,
    ),
    "./usr/bin/nvpn": (
        (root / executables["cli"]).read_bytes(),
        0o755,
    ),
    "./usr/share/applications/nostr-vpn.desktop": (
        (repo_root / "linux/resources/nostr-vpn.desktop").read_bytes(),
        0o644,
    ),
    "./usr/share/doc/nostr-vpn/copyright": (
        b"Format: https://www.debian.org/doc/packaging-manuals/"
        b"copyright-format/1.0/\n"
        b"Upstream-Name: nostr-vpn-linux\n"
        b"Copyright: Nostr VPN\n"
        b"License: UNLICENSED\n",
        0o644,
    ),
}
for size in (16, 22, 24, 32, 48, 64, 128, 256, 512):
    data_files[
        f"./usr/share/icons/hicolor/{size}x{size}/apps/nostr-vpn.png"
    ] = (
        (repo_root / f"linux/resources/nostr-vpn-{size}.png").read_bytes(),
        0o644,
    )
data_directories = set()
for name in data_files:
    parts = name.removeprefix("./").split("/")[:-1]
    for length in range(1, len(parts) + 1):
        data_directories.add(f"./{'/'.join(parts[:length])}")
installed_size = sum(
    1 + (len(raw) + 1023) // 1024 for raw, _mode in data_files.values()
)
depends = (
    "curl, libadwaita-1-0 (>= 1.5~beta), libc6 (>= 2.39), "
    "libcairo2 (>= 1.2.4), libdbus-1-3 (>= 1.9.14), "
    "libglib2.0-0t64 (>= 2.54.0), libgtk-4-1 (>= 4.12.0), "
    "xdg-utils, zbar-tools"
)
control = (
    "Package: nostr-vpn\n"
    f"Version: {app_version}-1\n"
    "Architecture: amd64\n"
    "Section: net\n"
    "Priority: optional\n"
    "Maintainer: Nostr VPN\n"
    f"Installed-Size: {installed_size}\n"
    f"Depends: {depends}\n"
    "Description: Simple private networks over FIPS and Nostr.\n"
    " Simple private networks over FIPS and Nostr.\n\n"
).encode()


def tar_xz(entries):
    output = io.BytesIO()
    with tarfile.open(
        fileobj=output, mode="w:xz", format=tarfile.USTAR_FORMAT
    ) as archive:
        for name, raw, mode, kind in entries:
            info = tarfile.TarInfo(name)
            info.size = len(raw)
            info.mode = mode
            info.mtime = 1
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            info.type = tarfile.DIRTYPE if kind == "dir" else tarfile.REGTYPE
            archive.addfile(info, None if kind == "dir" else io.BytesIO(raw))
    return output.getvalue()


control_tar = tar_xz([("./control", control, 0o644, "file")])
data_entries = [
    (name, b"", 0o755, "dir") for name in sorted(data_directories)
] + [
    (name, raw, mode, "file")
    for name, (raw, mode) in sorted(data_files.items())
]
data_tar = tar_xz(data_entries)


def ar_member(name, raw):
    header = (
        f"{name + '/':<16}"
        f"{1:<12}"
        f"{0:<6}"
        f"{0:<6}"
        f"{format(0o100644, 'o'):<8}"
        f"{len(raw):<10}"
        "`\n"
    ).encode("ascii")
    return header + raw + (b"\n" if len(raw) % 2 else b"")


deb = root / "nostr-vpn.deb"
deb.write_bytes(
    b"!<arch>\n"
    + ar_member("debian-binary", b"2.0\n")
    + ar_member("control.tar.xz", control_tar)
    + ar_member("data.tar.xz", data_tar)
)
deb.chmod(0o444)
artifacts["debianPackage"] = {
    "file": deb.name,
    "sha256": hashlib.sha256(deb.read_bytes()).hexdigest(),
    "size": deb.stat().st_size,
}
receipt = {
    "schema": 2,
    "builderMode": "remote-native",
    "builtOnHostMac": False,
    "builtOnRemoteVm": True,
    "builderHostOs": "Linux",
    "builderHostArchitecture": "x86_64",
    "containerImageId": container_image_id,
    "dockerfileSha256": dockerfile_sha,
    "containerPayloadSha256": payload_sha,
    "appGitSha": app_sha,
    "appGitTree": app_tree,
    "appVersion": app_version,
    "fipsGitSha": fips_sha,
    "fipsGitTree": fips_tree,
    "fipsVersion": fips_version,
    "rootCargoLockSha256": root_lock_sha,
    "rootRealizedCargoLockSha256": root_realized_lock_sha,
    "linuxCargoLockSha256": linux_lock_sha,
    "linuxRealizedCargoLockSha256": linux_realized_lock_sha,
    "fipsPatchedLockPackages": fips_patch_packages,
    "target": "x86_64-unknown-linux-gnu",
    "dockerPlatform": "linux/amd64",
    "containerBase": "ubuntu:24.04",
    "sourceDateEpoch": 1,
    "rustcVersion": f"rustc {rust_toolchain} (test)",
    "cargoVersion": f"cargo {rust_toolchain} (test)",
    "cliShortVersion": f"nvpn {app_version}",
    "cliVerboseVersion": f"fips_core: {fips_version} (rev {fips_sha[:10]})",
    "muslCliShortVersion": f"nvpn {app_version}",
    "muslCliVerboseVersion":
        f"fips_core: {fips_version} (rev {fips_sha[:10]})",
    "muslTarget": "x86_64-unknown-linux-musl",
    "cargoDebVersion": "3.7.0",
    "debianPackage": {
        "package": "nostr-vpn",
        "version": f"{app_version}-1",
        "architecture": "amd64",
        "appPath": "usr/bin/nostr-vpn",
        "cliPath": "usr/bin/nvpn",
    },
    "artifacts": artifacts,
}
(root / "receipt.json").write_text(
    json.dumps(receipt, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
PY
verify_fixture() {
  local mode="$1"
  python3 "$VERIFIER" \
    "$tmp" "$tmp/receipt.json" \
    "$app_sha" "$app_tree" "$app_version" \
    "$fips_sha" "$fips_tree" "$fips_version" \
    "$root_lock_sha" "$root_realized_lock_sha" \
    "$linux_lock_sha" "$linux_realized_lock_sha" \
    x86_64-unknown-linux-gnu "$mode" "$rust_toolchain" \
    "$dockerfile_sha" "$payload_sha" "${patch_specs[@]}"
}

verify_fixture remote-native \
  | grep -Fq HOST_LINUX_VM_BUNDLE_VERIFIED

cp "$tmp/receipt.json" "$backup/receipt-canonical-remote-native.json"
for adversary in \
  schema \
  builder-mode \
  host-flag \
  remote-flag \
  builder-os \
  builder-architecture \
  dockerfile \
  payload
do
  python3 - "$tmp/receipt.json" "$adversary" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
case = sys.argv[2]
receipt = json.loads(path.read_text(encoding="utf-8"))
mutations = {
    "schema": ("schema", 1),
    "builder-mode": ("builderMode", "local-docker"),
    "host-flag": ("builtOnHostMac", True),
    "remote-flag": ("builtOnRemoteVm", False),
    "builder-os": ("builderHostOs", "Darwin"),
    "builder-architecture": ("builderHostArchitecture", "arm64"),
    "dockerfile": ("dockerfileSha256", "0" * 64),
    "payload": ("containerPayloadSha256", "0" * 64),
}
key, value = mutations[case]
receipt[key] = value
path.write_text(
    json.dumps(receipt, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
PY
  if verify_fixture remote-native >/dev/null 2>&1; then
    fail "bundle verifier accepted forged $adversary builder provenance"
  fi
  cp "$backup/receipt-canonical-remote-native.json" "$tmp/receipt.json"
done

python3 - "$tmp/receipt.json" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
receipt = json.loads(path.read_text(encoding="utf-8"))
receipt.update(
    {
        "builderMode": "local-docker",
        "builtOnHostMac": True,
        "builtOnRemoteVm": False,
        "builderHostOs": "Darwin",
        "builderHostArchitecture": "x86_64",
    }
)
path.write_text(
    json.dumps(receipt, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
PY
verify_fixture local-docker >/dev/null \
  || fail "bundle verifier rejected exact local Docker provenance"
python3 - "$tmp/receipt.json" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
receipt = json.loads(path.read_text(encoding="utf-8"))
receipt["builderHostArchitecture"] = "arm64"
path.write_text(json.dumps(receipt), encoding="utf-8")
PY
if verify_fixture local-docker >/dev/null 2>&1; then
  fail "bundle verifier accepted an emulated arm64 local-docker amd64 build"
fi
cp "$backup/receipt-canonical-remote-native.json" "$tmp/receipt.json"

cp "$tmp/receipt.json" "$backup/receipt-before-realized-lock-adversary.json"
python3 - "$tmp/receipt.json" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
receipt = json.loads(path.read_text(encoding="utf-8"))
receipt["rootRealizedCargoLockSha256"] = "0" * 64
path.write_text(
    json.dumps(receipt, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
PY
if python3 "$VERIFIER" \
  "$tmp" "$tmp/receipt.json" \
  "$app_sha" "$app_tree" "$app_version" \
  "$fips_sha" "$fips_tree" "$fips_version" \
  "$root_lock_sha" "$root_realized_lock_sha" \
  "$linux_lock_sha" "$linux_realized_lock_sha" \
  x86_64-unknown-linux-gnu remote-native "$rust_toolchain" \
  "$dockerfile_sha" "$payload_sha" "${patch_specs[@]}" \
  >/dev/null 2>&1
then
  fail "bundle verifier accepted a mutated realized lock hash"
fi
mv "$backup/receipt-before-realized-lock-adversary.json" \
  "$tmp/receipt.json"

# A correctly hashed archive is still invalid if a glibc executable is put
# behind the public musl filename. This is the regression that allowed an
# earlier release path to mislabel the gate bundle's glibc CLI as static musl.
cp "$tmp/receipt.json" "$backup/receipt.json"
cp "$tmp/nvpn-x86_64-unknown-linux-musl.tar.gz" "$backup/archive.tar.gz"
chmod u+w "$tmp/nvpn-x86_64-unknown-linux-musl.tar.gz"
python3 - \
  "$tmp/receipt.json" \
  "$tmp/nvpn-x86_64-unknown-linux-musl.tar.gz" \
  "$tmp/nvpn" <<'PY'
import hashlib
import io
import json
import pathlib
import sys
import tarfile

receipt_path = pathlib.Path(sys.argv[1])
archive_path = pathlib.Path(sys.argv[2])
wrong_cli = pathlib.Path(sys.argv[3]).read_bytes()
with tarfile.open(archive_path, "w:gz") as archive:
    for name, raw, mode in (
        ("nvpn/README.txt", b"nvpn test\n", 0o444),
        ("nvpn/install.sh", b"#!/bin/sh\n", 0o555),
        ("nvpn/nvpn", wrong_cli, 0o555),
    ):
        info = tarfile.TarInfo(name)
        info.size = len(raw)
        info.mode = mode
        archive.addfile(info, io.BytesIO(raw))
receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
entry = receipt["artifacts"]["muslCliArchive"]
entry["sha256"] = hashlib.sha256(archive_path.read_bytes()).hexdigest()
entry["size"] = archive_path.stat().st_size
receipt_path.write_text(
    json.dumps(receipt, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
PY
if python3 "$VERIFIER" \
  "$tmp" "$tmp/receipt.json" \
  "$app_sha" "$app_tree" "$app_version" \
  "$fips_sha" "$fips_tree" "$fips_version" \
  "$root_lock_sha" "$root_realized_lock_sha" \
  "$linux_lock_sha" "$linux_realized_lock_sha" \
  x86_64-unknown-linux-gnu remote-native "$rust_toolchain" \
  "$dockerfile_sha" "$payload_sha" "${patch_specs[@]}" \
  >/dev/null 2>&1
then
  fail "bundle verifier accepted a glibc CLI mislabeled as static musl"
fi
mv "$backup/receipt.json" "$tmp/receipt.json"
mv "$backup/archive.tar.gz" \
  "$tmp/nvpn-x86_64-unknown-linux-musl.tar.gz"

# A self-consistent receipt must not bless changed installer bytes or modes:
# every public archive member is part of the release payload.
cp "$tmp/receipt.json" "$backup/receipt-before-archive-content-adversary.json"
cp "$tmp/nvpn-x86_64-unknown-linux-musl.tar.gz" \
  "$backup/archive-before-content-adversary.tar.gz"
chmod u+w "$tmp/nvpn-x86_64-unknown-linux-musl.tar.gz"
python3 - \
  "$tmp/receipt.json" \
  "$tmp/nvpn-x86_64-unknown-linux-musl.tar.gz" <<'PY'
import hashlib
import io
import json
import pathlib
import sys
import tarfile

receipt_path = pathlib.Path(sys.argv[1])
archive_path = pathlib.Path(sys.argv[2])
with tarfile.open(archive_path, "r:gz") as archive:
    members = {
        member.name: (archive.extractfile(member).read(), member.mode)
        for member in archive.getmembers()
    }
members["nvpn/install.sh"] = (b"#!/bin/sh\nexit 0\n", 0o755)
with tarfile.open(archive_path, "w:gz") as archive:
    for name in ("nvpn/README.txt", "nvpn/install.sh", "nvpn/nvpn"):
        raw, mode = members[name]
        info = tarfile.TarInfo(name)
        info.size = len(raw)
        info.mode = mode
        archive.addfile(info, io.BytesIO(raw))
receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
entry = receipt["artifacts"]["muslCliArchive"]
entry["sha256"] = hashlib.sha256(archive_path.read_bytes()).hexdigest()
entry["size"] = archive_path.stat().st_size
receipt_path.write_text(
    json.dumps(receipt, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
PY
if verify_fixture remote-native >/dev/null 2>&1; then
  fail "bundle verifier accepted self-consistent forged archive installer bytes"
fi
mv "$backup/receipt-before-archive-content-adversary.json" "$tmp/receipt.json"
mv "$backup/archive-before-content-adversary.tar.gz" \
  "$tmp/nvpn-x86_64-unknown-linux-musl.tar.gz"

cp "$tmp/receipt.json" "$backup/receipt-before-archive-mode-adversary.json"
cp "$tmp/nvpn-x86_64-unknown-linux-musl.tar.gz" \
  "$backup/archive-before-mode-adversary.tar.gz"
chmod u+w "$tmp/nvpn-x86_64-unknown-linux-musl.tar.gz"
python3 - \
  "$tmp/receipt.json" \
  "$tmp/nvpn-x86_64-unknown-linux-musl.tar.gz" <<'PY'
import hashlib
import io
import json
import pathlib
import sys
import tarfile

receipt_path = pathlib.Path(sys.argv[1])
archive_path = pathlib.Path(sys.argv[2])
with tarfile.open(archive_path, "r:gz") as archive:
    entries = []
    for member in archive.getmembers():
        content = archive.extractfile(member).read()
        if member.name == "nvpn/install.sh":
            member.mode = 0o755
        entries.append((member, content))
with tarfile.open(
    archive_path, "w:gz", format=tarfile.USTAR_FORMAT
) as archive:
    for member, content in entries:
        archive.addfile(member, io.BytesIO(content))
receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
entry = receipt["artifacts"]["muslCliArchive"]
entry["sha256"] = hashlib.sha256(archive_path.read_bytes()).hexdigest()
entry["size"] = archive_path.stat().st_size
receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
PY
if verify_fixture remote-native >/dev/null 2>&1; then
  fail "bundle verifier accepted a self-consistent archive mode mutation"
fi
mv "$backup/receipt-before-archive-mode-adversary.json" "$tmp/receipt.json"
mv "$backup/archive-before-mode-adversary.tar.gz" \
  "$tmp/nvpn-x86_64-unknown-linux-musl.tar.gz"

# The DEB must be parsed and completely allowlisted before dpkg can execute it.
# Both attacks update the outer package hash and receipt self-consistently.
cp "$tmp/receipt.json" "$backup/receipt-before-deb-adversary.json"
cp "$tmp/nostr-vpn.deb" "$backup/deb-before-adversary.deb"
for deb_adversary in preinst setuid-extra; do
  cp "$backup/receipt-before-deb-adversary.json" "$tmp/receipt.json"
  chmod u+w "$tmp/nostr-vpn.deb"
  cp "$backup/deb-before-adversary.deb" "$tmp/nostr-vpn.deb"
  python3 - \
    "$tmp/receipt.json" "$tmp/nostr-vpn.deb" "$deb_adversary" <<'PY'
import hashlib
import io
import json
import lzma
import pathlib
import sys
import tarfile

receipt_path = pathlib.Path(sys.argv[1])
deb_path = pathlib.Path(sys.argv[2])
case = sys.argv[3]
raw_deb = deb_path.read_bytes()
if not raw_deb.startswith(b"!<arch>\n"):
    raise SystemExit("test DEB is not ar")
offset = 8
members = []
while offset < len(raw_deb):
    header = raw_deb[offset : offset + 60]
    offset += 60
    name = header[:16].decode("ascii").strip().removesuffix("/")
    size = int(header[48:58].decode("ascii").strip())
    members.append((name, raw_deb[offset : offset + size]))
    offset += size + size % 2
by_name = dict(members)
target = "control.tar.xz" if case == "preinst" else "data.tar.xz"
with tarfile.open(
    fileobj=io.BytesIO(lzma.decompress(by_name[target])), mode="r:"
) as source:
    entries = []
    for member in source.getmembers():
        content = source.extractfile(member).read() if member.isfile() else b""
        entries.append((member, content))
extra = tarfile.TarInfo(
    "./preinst" if case == "preinst" else "./usr/bin/extra-root"
)
extra.mode = 0o755 if case == "preinst" else 0o4755
extra.mtime = 1
extra.uid = 0
extra.gid = 0
extra.uname = ""
extra.gname = ""
extra_content = b"#!/bin/sh\nexit 0\n"
extra.size = len(extra_content)
entries.append((extra, extra_content))
rebuilt = io.BytesIO()
with tarfile.open(
    fileobj=rebuilt, mode="w:xz", format=tarfile.USTAR_FORMAT
) as archive:
    for member, content in entries:
        archive.addfile(
            member,
            io.BytesIO(content) if member.isfile() else None,
        )
by_name[target] = rebuilt.getvalue()


def ar_member(name, raw):
    header = (
        f"{name + '/':<16}"
        f"{1:<12}"
        f"{0:<6}"
        f"{0:<6}"
        f"{format(0o100644, 'o'):<8}"
        f"{len(raw):<10}"
        "`\n"
    ).encode("ascii")
    return header + raw + (b"\n" if len(raw) % 2 else b"")


deb_path.write_bytes(
    b"!<arch>\n"
    + b"".join(ar_member(name, by_name[name]) for name, _raw in members)
)
receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
entry = receipt["artifacts"]["debianPackage"]
entry["sha256"] = hashlib.sha256(deb_path.read_bytes()).hexdigest()
entry["size"] = deb_path.stat().st_size
receipt_path.write_text(
    json.dumps(receipt, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
PY
  if verify_fixture remote-native >/dev/null 2>&1; then
    fail "bundle verifier accepted a self-consistent DEB $deb_adversary payload"
  fi
done
mv "$backup/receipt-before-deb-adversary.json" "$tmp/receipt.json"
mv "$backup/deb-before-adversary.deb" "$tmp/nostr-vpn.deb"

chmod u+w "$tmp/nvpn"
printf x >>"$tmp/nvpn"
if python3 "$VERIFIER" \
  "$tmp" "$tmp/receipt.json" \
  "$app_sha" "$app_tree" "$app_version" \
  "$fips_sha" "$fips_tree" "$fips_version" \
  "$root_lock_sha" "$root_realized_lock_sha" \
  "$linux_lock_sha" "$linux_realized_lock_sha" \
  x86_64-unknown-linux-gnu remote-native "$rust_toolchain" \
  "$dockerfile_sha" "$payload_sha" "${patch_specs[@]}" \
  >/dev/null 2>&1
then
  fail "bundle verifier accepted a post-receipt CLI mutation"
fi

echo "HOST_LINUX_VM_IMPORT_ONLY_CONTRACT_OK"
