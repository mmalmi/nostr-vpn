#!/usr/bin/env python3
"""Require an already published dependency to contain this checkout's sources."""
import pathlib
import sys
import tarfile


def verify(crate, version, directory, archive, package_files):
    root = pathlib.Path(directory).resolve(strict=True)
    prefix = f"{crate}-{version}/"
    # Cargo regenerates these from the consuming workspace/compiler. Library
    # lockfiles do not control consumers; the CLI's packaged lockfile does.
    generated = {"Cargo.toml", "Cargo.lock", ".cargo_vcs_info.json"}
    expected = set(package_files) - generated
    with tarfile.open(archive) as package:
        files = {}
        for item in package.getmembers():
            if item.isdir():
                continue
            if not item.isfile():
                raise ValueError("registry package contains a non-regular file")
            if not item.name.startswith(prefix):
                raise ValueError("registry package has an unexpected root")
            name = item.name[len(prefix):]
            if name in generated:
                continue
            if name in files or pathlib.PurePosixPath(name).is_absolute() or ".." in pathlib.PurePosixPath(name).parts:
                raise ValueError("registry package has an invalid file path")
            files[name] = package.extractfile(item).read()
    if set(files) != expected:
        raise ValueError("local and published dependency file lists differ")
    for name, payload in files.items():
        relative = "Cargo.toml" if name == "Cargo.toml.orig" else name
        path = root / relative
        if path.is_symlink() or not path.is_file() or path.read_bytes() != payload:
            raise ValueError(f"published dependency source differs: {name}; bump {crate}'s version")
    return len(files)


if __name__ == "__main__":
    try:
        count = verify(*sys.argv[1:], sys.stdin.read().splitlines())
        print(f"[ok] {sys.argv[1]} {sys.argv[2]}: {count} published source files match")
    except (OSError, ValueError, tarfile.TarError) as error:
        raise SystemExit(str(error))
