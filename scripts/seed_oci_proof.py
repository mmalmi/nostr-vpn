#!/usr/bin/env python3
"""Read the bounded single-platform OCI export without unpacking a filesystem."""
import gzip
import hashlib
import io
import json
import re
import tarfile

from seed_hosted_proof import require, sha256

TARGETS = ("usr/local/bin/nvpn", "usr/local/bin/nvpn-web")
MAX_UNPACKED = 4 * 1024**3


class HashReader:
    def __init__(self, stream, remaining):
        self.stream = stream
        self.limit = remaining
        self.count = 0
        self.digest = hashlib.sha256()

    def read(self, size=-1):
        data = self.stream.read(65536 if size < 0 else min(size, 65536))
        self.count += len(data)
        require(self.count <= self.limit, "OCI decompression bound exceeded")
        self.digest.update(data)
        return data


def clean_path(name):
    name = name.removeprefix("./").rstrip("/")
    require(not name.startswith("/") and ".." not in name.split("/"),
            "Unsafe OCI path")
    return name


def read_json(archive, member, limit):
    require(member.isfile() and 0 < member.size <= limit, "Invalid OCI JSON size")
    data = archive.extractfile(member).read(limit + 1)
    require(len(data) == member.size, "Truncated OCI JSON")
    def unique(pairs):
        out = {}
        for key, value in pairs:
            require(key not in out, "Duplicate OCI JSON key")
            out[key] = value
        return out
    return json.loads(data, object_pairs_hook=unique), data


def verify_oci(stream, maximum, expected_metadata_digest):
    require(stream.seek(0, 2) <= maximum, "OCI file extent exceeded")
    stream.seek(0)
    archive = tarfile.open(fileobj=stream, mode="r:")
    members = {}
    total = 0
    for member in archive:
        name = clean_path(member.name)
        if member.isdir():
            require(name in ("", "blobs", "blobs/sha256"), "Unexpected OCI directory")
            continue
        require(member.isfile() and name not in members, "Invalid or duplicate OCI entry")
        require(name in ("index.json", "oci-layout") or
                re.fullmatch(r"blobs/sha256/[0-9a-f]{64}", name), "Unexpected OCI entry")
        total += member.size
        require(0 <= member.size <= maximum and total <= maximum and len(members) < 4096,
                "OCI archive bound exceeded")
        members[name] = member
    require("oci-layout" in members and "index.json" in members, "Missing OCI index")
    layout, _ = read_json(archive, members["oci-layout"], 1024)
    require(layout == {"imageLayoutVersion": "1.0.0"}, "Unsupported OCI layout")
    index, index_bytes = read_json(archive, members["index.json"], 4 * 1024**2)
    require(index.get("schemaVersion") == 2 and len(index.get("manifests", [])) == 1,
            "Expected one OCI image")
    referenced = set()

    def blob(descriptor):
        digest = descriptor.get("digest", "")
        require(re.fullmatch(r"sha256:[0-9a-f]{64}", digest), "Invalid OCI digest")
        name = "blobs/sha256/" + digest[7:]
        require(name in members and type(descriptor.get("size")) is int and
                descriptor["size"] == members[name].size, "OCI descriptor size mismatch")
        digest_actual = hashlib.sha256()
        handle = archive.extractfile(members[name])
        while data := handle.read(65536):
            digest_actual.update(data)
        require("sha256:" + digest_actual.hexdigest() == digest, "OCI blob digest mismatch")
        referenced.add(name)
        return members[name]

    descriptor = index["manifests"][0]
    manifest_member = blob(descriptor)
    manifest, _ = read_json(archive, manifest_member, 4 * 1024**2)
    require(descriptor["digest"] == expected_metadata_digest,
            "Buildx digest differs from exported image")
    require(manifest.get("schemaVersion") == 2 and manifest.get("layers"),
            "Unsupported OCI image manifest")
    config_member = blob(manifest["config"])
    config, _ = read_json(archive, config_member, 1024**2)
    require(config.get("os") == "linux" and config.get("architecture") == "amd64",
            "Wrong candidate platform")
    diff_ids = config.get("rootfs", {}).get("diff_ids", [])
    require(len(diff_ids) == len(manifest["layers"]), "OCI rootfs layer count mismatch")
    executables = {}
    unpacked = 0
    entries = 0
    for number, layer in enumerate(manifest["layers"]):
        member = blob(layer)
        require(layer.get("mediaType") == "application/vnd.oci.image.layer.v1.tar+gzip",
                "Unsupported OCI layer compression")
        raw = gzip.GzipFile(fileobj=archive.extractfile(member))
        reader = HashReader(raw, MAX_UNPACKED - unpacked)
        with tarfile.open(fileobj=reader, mode="r|") as contents:
            for entry in contents:
                entries += 1
                require(entries <= 100000 and 0 <= entry.size <= MAX_UNPACKED,
                        "OCI layer extent exceeded")
                name = clean_path(entry.name)
                parent, _, base = name.rpartition("/")
                for target in TARGETS:
                    removed = (parent + "/" if parent else "") + base[4:]
                    if base == ".wh..wh..opq" and (not parent or target.startswith(parent + "/")):
                        executables.pop(target, None)
                    elif base.startswith(".wh.") and (target == removed or
                                                       target.startswith(removed + "/")):
                        executables.pop(target, None)
                    elif target.startswith(name + "/"):
                        require(entry.isdir(), "Executable ancestor is not a directory")
                if name not in TARGETS:
                    continue
                require(entry.isfile() and 64 <= entry.size <= 256 * 1024**2 and
                        entry.mode == 0o755, "Invalid candidate executable")
                handle = contents.extractfile(entry)
                first = handle.read(64)
                require(first[:6] == b"\x7fELF\x02\x01" and first[18:20] == b"\x3e\x00",
                        "Candidate is not Linux amd64 ELF")
                digest = hashlib.sha256(first)
                size = len(first)
                while data := handle.read(65536):
                    digest.update(data)
                    size += len(data)
                require(size == entry.size, "Truncated candidate ELF")
                executables[name] = {"sha256": digest.hexdigest(), "bytes": size, "mode": "0755"}
        while reader.read(65536):
            pass
        require("sha256:" + reader.digest.hexdigest() == diff_ids[number],
                "OCI uncompressed layer digest mismatch")
        unpacked += reader.count
    require(set(executables) == set(TARGETS), "Missing final candidate executable")
    require(referenced == {name for name in members if name.startswith("blobs/")},
            "OCI contains unreferenced payload")
    return {"indexSha256": sha256(index_bytes), "manifestDigest": descriptor["digest"],
            "configDigest": manifest["config"]["digest"], "platform": "linux/amd64",
            "executables": executables, "compressedPayloadBytes": total,
            "uncompressedLayerBytes": unpacked, "layerCount": len(manifest["layers"])}
