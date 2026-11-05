#!/usr/bin/env python3
"""Reset or remove only the directory created by this Linux release gate."""
import json
import os
from pathlib import Path
import shutil
import stat
import sys


def identity(metadata):
    return [metadata.st_dev, metadata.st_ino, metadata.st_uid, metadata.st_gid]


def parent_identities(profile):
    result = []
    for parent in profile.parents:
        metadata = parent.lstat()
        if not stat.S_ISDIR(metadata.st_mode):
            raise RuntimeError("test-profile parent is not a real directory")
        result.append([str(parent), identity(metadata)])
    return result


def manage_profile(profile: Path, ownership: Path, *, cleanup=False):
    if not profile.is_absolute() or ".." in profile.parts:
        raise RuntimeError("test profile must have an absolute, normalized path")
    if not ownership.exists() and not ownership.is_symlink():
        if profile.exists() or profile.is_symlink():
            raise RuntimeError("preserve the existing CLI profile before this gate")
        if cleanup:
            return
        profile.parent.mkdir(parents=True, exist_ok=True)
        parents = parent_identities(profile)
        profile.mkdir(mode=0o700)
        proof = {"schema": 1, "path": str(profile), "parents": parents,
                 "directory": identity(profile.lstat())}
        with ownership.open("x") as output:
            json.dump(proof, output)
    else:
        descriptor = os.open(ownership, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(descriptor) as source:
            if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
                raise RuntimeError("test-profile ownership is not a regular file")
            proof = json.load(source)
    if (proof.get("schema") != 1 or proof.get("path") != str(profile)
            or proof.get("parents") != parent_identities(profile)):
        raise RuntimeError("test-profile ownership or parent identity changed")
    if cleanup and not profile.exists() and not profile.is_symlink():
        return
    parent_fd = os.open(profile.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        if identity(os.fstat(parent_fd)) != proof["parents"][0][1]:
            raise RuntimeError("test-profile parent identity changed")
        descriptor = os.open(profile.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                             dir_fd=parent_fd)
        try:
            if identity(os.fstat(descriptor)) != proof.get("directory"):
                raise RuntimeError("test-profile directory identity changed")
            # Relative operations stay attached to the verified directory even
            # if a pathname is replaced. Never follow links into another profile.
            for name in os.listdir(descriptor):
                metadata = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
                if stat.S_ISDIR(metadata.st_mode):
                    shutil.rmtree(name, dir_fd=descriptor)
                else:
                    os.unlink(name, dir_fd=descriptor)
            if cleanup:
                current = os.stat(profile.name, dir_fd=parent_fd, follow_symlinks=False)
                if identity(current) != proof["directory"]:
                    raise RuntimeError("test-profile directory changed before removal")
                os.rmdir(profile.name, dir_fd=parent_fd)
        finally:
            os.close(descriptor)
    finally:
        os.close(parent_fd)


if __name__ == "__main__":
    if len(sys.argv) != 4 or sys.argv[1] not in {"reset", "cleanup"}:
        raise SystemExit("usage: linux_release_profile.py reset|cleanup PROFILE OWNERSHIP")
    manage_profile(Path(sys.argv[2]), Path(sys.argv[3]), cleanup=sys.argv[1] == "cleanup")
