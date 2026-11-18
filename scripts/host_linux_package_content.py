#!/usr/bin/env python3
"""Canonical, non-executing validation for Linux release package contents."""

from __future__ import annotations

import hashlib
import io
import json
import lzma
import pathlib
import re
import stat
import sys
import tarfile
import zlib
from dataclasses import dataclass
from typing import NoReturn


class PackageVerificationError(ValueError):
    """The package differs from the exact release payload."""


def reject(message: str) -> NoReturn:
    raise PackageVerificationError(message)


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


@dataclass(frozen=True)
class ArMember:
    name: str
    mtime: int
    uid: int
    gid: int
    mode: int
    data: bytes


def read_ar(path: pathlib.Path) -> list[ArMember]:
    raw = path.read_bytes()
    if not raw.startswith(b"!<arch>\n"):
        reject("Debian package is not an ar archive")
    offset = 8
    members: list[ArMember] = []
    while offset < len(raw):
        if len(raw) - offset < 60:
            reject("Debian ar archive has trailing or truncated bytes")
        header = raw[offset : offset + 60]
        offset += 60
        if header[58:60] != b"`\n":
            reject("Debian ar member header is malformed")
        try:
            raw_name = header[0:16].decode("ascii").rstrip()
            mtime = int(header[16:28].decode("ascii").strip(), 10)
            uid = int(header[28:34].decode("ascii").strip(), 10)
            gid = int(header[34:40].decode("ascii").strip(), 10)
            mode = int(header[40:48].decode("ascii").strip(), 8)
            size = int(header[48:58].decode("ascii").strip(), 10)
        except (UnicodeDecodeError, ValueError) as error:
            reject(f"Debian ar member metadata is malformed: {error}")
        if raw_name.startswith(("/", "#1/", "//")):
            reject("Debian ar archive uses an extended or absolute member name")
        name = raw_name.removesuffix("/")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.+-]*", name):
            reject("Debian ar archive has an unsafe member name")
        if size < 0 or offset + size > len(raw):
            reject("Debian ar member size is invalid")
        data = raw[offset : offset + size]
        offset += size
        if size % 2:
            if offset >= len(raw) or raw[offset : offset + 1] != b"\n":
                reject("Debian ar member padding is invalid")
            offset += 1
        members.append(ArMember(name, mtime, uid, gid, mode, data))
    if len({member.name for member in members}) != len(members):
        reject("Debian ar archive has duplicate members")
    return members


def decompress_single_xz(raw: bytes, label: str) -> bytes:
    decoder = lzma.LZMADecompressor(format=lzma.FORMAT_XZ)
    try:
        value = decoder.decompress(raw)
    except lzma.LZMAError as error:
        reject(f"{label} is not a valid XZ stream: {error}")
    if not decoder.eof or decoder.unused_data:
        reject(f"{label} is truncated or contains concatenated/trailing data")
    return value


def decompress_single_gzip(raw: bytes, label: str) -> bytes:
    decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
    try:
        value = decoder.decompress(raw) + decoder.flush()
    except zlib.error as error:
        reject(f"{label} is not a valid gzip stream: {error}")
    if not decoder.eof or decoder.unused_data or decoder.unconsumed_tail:
        reject(f"{label} is truncated or contains concatenated/trailing data")
    return value


def read_tar(raw: bytes, label: str) -> list[tuple[tarfile.TarInfo, bytes]]:
    result: list[tuple[tarfile.TarInfo, bytes]] = []
    try:
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
            members = archive.getmembers()
            names = [member.name for member in members]
            if len(names) != len(set(names)):
                reject(f"{label} has duplicate members")
            for member in members:
                content = b""
                if member.isfile():
                    source = archive.extractfile(member)
                    if source is None:
                        reject(f"{label} member {member.name} is unreadable")
                    content = source.read()
                    if len(content) != member.size:
                        reject(f"{label} member {member.name} is truncated")
                result.append((member, content))
    except (tarfile.TarError, OSError) as error:
        reject(f"{label} is not a valid tar archive: {error}")
    end = max(
        (
            member.offset_data + ((member.size + 511) // 512) * 512
            for member, _content in result
        ),
        default=0,
    )
    if len(raw) < end + 1024 or any(raw[end:]):
        reject(f"{label} has noncanonical trailing tar data")
    return result


def require_tar_member(
    member: tarfile.TarInfo,
    *,
    name: str,
    kind: str,
    mode: int,
    source_date_epoch: int,
) -> None:
    if member.name != name or pathlib.PurePosixPath(name).is_absolute():
        reject(f"archive member path differs from exact payload: {member.name}")
    if ".." in pathlib.PurePosixPath(name).parts:
        reject(f"archive member path traverses outside payload: {member.name}")
    if member.pax_headers:
        reject(f"archive member has unexpected extended metadata: {name}")
    if kind == "file" and not member.isfile():
        reject(f"archive member is not a regular file: {name}")
    if kind == "dir" and not member.isdir():
        reject(f"archive member is not a directory: {name}")
    if member.mode != mode or member.uid != 0 or member.gid != 0:
        reject(f"archive member mode or ownership differs: {name}")
    if member.uname or member.gname or member.mtime != source_date_epoch:
        reject(f"archive member identity or timestamp differs: {name}")
    if member.issym() or member.islnk() or member.isdev():
        reject(f"archive member has an unsafe type: {name}")


def expected_deb_payload(
    repo_root: pathlib.Path,
    app_sha256: str,
    cli_sha256: str,
) -> tuple[dict[str, tuple[str, int, bytes | str]], set[str]]:
    files: dict[str, tuple[str, int, bytes | str]] = {
        "./usr/bin/nostr-vpn": ("file", 0o755, app_sha256),
        "./usr/bin/nvpn": ("file", 0o755, cli_sha256),
        "./usr/share/applications/nostr-vpn.desktop": (
            "file",
            0o644,
            (repo_root / "linux/resources/nostr-vpn.desktop").read_bytes(),
        ),
        "./usr/share/applications/fi.siriusbusiness.nvpn.desktop": (
            "file", 0o644, (repo_root / "linux/resources/fi.siriusbusiness.nvpn.desktop").read_bytes(),
        ),
        "./usr/share/Thunar/sendto/nvpn.desktop": (
            "file", 0o644, (repo_root / "linux/resources/nvpn-sendto.desktop").read_bytes(),
        ),
        "./usr/share/kio/servicemenus/nvpn-sendfiles.desktop": (
            "file", 0o644, (repo_root / "linux/resources/nvpn-sendfiles.desktop").read_bytes(),
        ),
        "./usr/share/doc/nostr-vpn/copyright": (
            "file",
            0o644,
            (
                b"Format: https://www.debian.org/doc/packaging-manuals/"
                b"copyright-format/1.0/\n"
                b"Upstream-Name: nostr-vpn-linux\n"
                b"Copyright: Nostr VPN\n"
                b"License: UNLICENSED\n"
            ),
        ),
    }
    for size in (16, 22, 24, 32, 48, 64, 128, 256, 512):
        files[
            f"./usr/share/icons/hicolor/{size}x{size}/apps/nostr-vpn.png"
        ] = (
            "file",
            0o644,
            (repo_root / f"linux/resources/nostr-vpn-{size}.png").read_bytes(),
        )
    directories: set[str] = set()
    for name in files:
        parts = name.removeprefix("./").split("/")[:-1]
        for length in range(1, len(parts) + 1):
            directories.add(f"./{'/'.join(parts[:length])}")
    return files, directories


def verify_debian_package(
    *,
    repo_root: pathlib.Path,
    deb_path: pathlib.Path,
    app_version: str,
    source_date_epoch: int,
    app_sha256: str,
    cli_sha256: str,
) -> None:
    members = read_ar(deb_path)
    if [member.name for member in members] != [
        "debian-binary",
        "control.tar.xz",
        "data.tar.xz",
    ]:
        reject("Debian ar archive has extra, missing, or reordered members")
    for member in members:
        if (
            member.mtime != source_date_epoch
            or member.uid != 0
            or member.gid != 0
            or stat.S_IMODE(member.mode) != 0o644
        ):
            reject(f"Debian ar member metadata differs: {member.name}")
    by_name = {member.name: member.data for member in members}
    if by_name["debian-binary"] != b"2.0\n":
        reject("Debian binary format marker differs")

    control_raw = decompress_single_xz(
        by_name["control.tar.xz"], "Debian control archive"
    )
    control_members = read_tar(control_raw, "Debian control archive")
    if [member.name for member, _content in control_members] != ["./control"]:
        reject("Debian control archive contains a maintainer script or extra payload")
    control, control_content = control_members[0]
    require_tar_member(
        control,
        name="./control",
        kind="file",
        mode=0o644,
        source_date_epoch=source_date_epoch,
    )

    data_raw = decompress_single_xz(by_name["data.tar.xz"], "Debian data archive")
    data_members = read_tar(data_raw, "Debian data archive")
    files, directories = expected_deb_payload(
        repo_root, app_sha256, cli_sha256
    )
    expected_names = {*files, *directories}
    actual_names = {member.name for member, _content in data_members}
    if actual_names != expected_names or len(data_members) != len(expected_names):
        reject("Debian data archive has an extra or missing payload path")
    # cargo-deb accounts one additional KiB of metadata/block overhead for
    # every installed regular file.
    installed_size = 0
    for member, content in data_members:
        if member.name in directories:
            require_tar_member(
                member,
                name=member.name,
                kind="dir",
                mode=0o755,
                source_date_epoch=source_date_epoch,
            )
            if member.size != 0:
                reject(f"Debian directory has content bytes: {member.name}")
            continue
        _kind, mode, expected = files[member.name]
        require_tar_member(
            member,
            name=member.name,
            kind="file",
            mode=mode,
            source_date_epoch=source_date_epoch,
        )
        installed_size += 1 + (len(content) + 1023) // 1024
        if isinstance(expected, bytes):
            if content != expected:
                reject(f"Debian source asset bytes differ: {member.name}")
        elif sha256_bytes(content) != expected:
            reject(f"Debian executable bytes differ: {member.name}")

    depends = (
        "curl, iproute2, libadwaita-1-0 (>= 1.5~beta), libc6 (>= 2.39), "
        "libcairo2 (>= 1.2.4), libdbus-1-3 (>= 1.9.14), "
        "libglib2.0-0t64 (>= 2.54.0), libgtk-4-1 (>= 4.12.0), "
        "nftables, xdg-utils, zbar-tools"
    )
    expected_control = (
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
    if control_content != expected_control:
        reject("Debian control metadata differs from the exact candidate")


def verify_musl_archive(
    *,
    archive_path: pathlib.Path,
    source_date_epoch: int,
    musl_cli_sha256: str,
) -> None:
    raw = decompress_single_gzip(
        archive_path.read_bytes(), "static Linux CLI archive"
    )
    members = read_tar(raw, "static Linux CLI archive")
    expected = [
        (
            "nvpn/README.txt",
            0o644,
            b"nvpn - FIPS private mesh CLI\n",
        ),
        (
            "nvpn/install.sh",
            0o555,
            (
                b"#!/bin/bash\n"
                b"set -e\n"
                b'install -d "${1:-/usr/local/bin}"\n'
                b'install -m 755 nvpn "${1:-/usr/local/bin}/"\n'
            ),
        ),
        ("nvpn/nvpn", 0o555, musl_cli_sha256),
    ]
    if [member.name for member, _content in members] != [
        name for name, _mode, _expected in expected
    ]:
        reject("static Linux CLI archive has an extra or missing member")
    for (member, content), (name, mode, expected_content) in zip(
        members, expected
    ):
        require_tar_member(
            member,
            name=name,
            kind="file",
            mode=mode,
            source_date_epoch=source_date_epoch,
        )
        if isinstance(expected_content, bytes):
            if content != expected_content:
                reject(f"static Linux CLI archive bytes differ: {name}")
        elif sha256_bytes(content) != expected_content:
            reject("static Linux CLI archive executable differs")


def main() -> None:
    if len(sys.argv) != 5:
        raise SystemExit(
            "usage: host_linux_package_content.py "
            "REPO_ROOT DEB MUSL_ARCHIVE RECEIPT"
        )
    repo_root, deb, archive, receipt_path = map(pathlib.Path, sys.argv[1:])
    try:
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        artifacts = receipt["artifacts"]
        verify_debian_package(
            repo_root=repo_root,
            deb_path=deb,
            app_version=receipt["appVersion"],
            source_date_epoch=receipt["sourceDateEpoch"],
            app_sha256=artifacts["app"]["sha256"],
            cli_sha256=artifacts["cli"]["sha256"],
        )
        verify_musl_archive(
            archive_path=archive,
            source_date_epoch=receipt["sourceDateEpoch"],
            musl_cli_sha256=artifacts["muslCli"]["sha256"],
        )
    except (
        KeyError,
        OSError,
        TypeError,
        ValueError,
        json.JSONDecodeError,
    ) as error:
        raise SystemExit(
            f"host Linux package content verification failed: {error}"
        ) from error
    print("HOST_LINUX_PACKAGE_CONTENT_VERIFIED")


if __name__ == "__main__":
    main()
