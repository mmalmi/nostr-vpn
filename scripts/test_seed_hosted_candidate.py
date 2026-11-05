#!/usr/bin/env python3
"""No Docker, network, compiler, credentials or release effects."""
import copy
import gzip
import hashlib
import io
import json
import stat
import tarfile
import types
import unittest
from unittest.mock import patch
from pathlib import Path

from seed_hosted_candidate import build_arguments
from seed_hosted_runtime import Runner

from seed_hosted_proof import (GIB, admission, canonical, owned_resource,
                               resource_check, sha256, verify_cached_export, verify_source, verify_toolchain)
from seed_oci_proof import TARGETS, verify_oci


def tar_bytes(entries):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as archive:
        for name, data, mode in entries:
            member = tarfile.TarInfo(name)
            member.size = len(data)
            member.mode = mode
            archive.addfile(member, io.BytesIO(data))
    return output.getvalue()


def oci(architecture="amd64", elf_machine=b"\x3e\x00", mode=0o755,
        extra_blob=False, bad_diff=False, whiteout=False):
    header = bytearray(64)
    header[:6] = b"\x7fELF\x02\x01"
    header[18:20] = elf_machine
    layers = [tar_bytes([(name, bytes(header), mode) for name in TARGETS])]
    if whiteout:
        layers.append(tar_bytes([("usr/local/bin/.wh.nvpn", b"", 0o644)]))
    blobs = {}

    def add(data, media):
        digest = sha256(data)
        blobs["blobs/sha256/" + digest] = data
        return {"mediaType": media, "digest": "sha256:" + digest, "size": len(data)}

    descriptors = [add(gzip.compress(data, mtime=0),
                       "application/vnd.oci.image.layer.v1.tar+gzip") for data in layers]
    config = {"os": "linux", "architecture": architecture,
              "rootfs": {"type": "layers", "diff_ids": [
                  "sha256:" + ("0" * 64 if bad_diff else sha256(data)) for data in layers]}}
    conf = add(canonical(config), "application/vnd.oci.image.config.v1+json")
    manifest = add(canonical({"schemaVersion": 2, "config": conf, "layers": descriptors}),
                   "application/vnd.oci.image.manifest.v1+json")
    index = canonical({"schemaVersion": 2, "manifests": [manifest]})
    if extra_blob:
        blobs["blobs/sha256/" + sha256(b"unreferenced")] = b"unreferenced"
    entries = [("oci-layout", canonical({"imageLayoutVersion": "1.0.0"}), 0o644),
               ("index.json", index, 0o644)]
    entries.extend((name, value, 0o644) for name, value in blobs.items())
    return tar_bytes(entries), manifest["digest"]


class OciTests(unittest.TestCase):
    def check(self, data, digest, maximum=4 * 1024**2):
        return verify_oci(io.BytesIO(data), maximum, digest)

    def test_exact_image_binds_final_two_executables(self):
        data, digest = oci()
        result = self.check(data, digest)
        self.assertEqual(result["manifestDigest"], digest)
        self.assertEqual(set(result["executables"]), set(TARGETS))
        self.assertTrue(all(x["bytes"] == 64 for x in result["executables"].values()))

    def test_content_tamper(self):
        data, digest = oci()
        marker = b'"imageLayoutVersion":"1.0.0"'
        with self.assertRaises(ValueError):
            self.check(data.replace(marker, b'"imageLayoutVersion":"9.9.9"'), digest)

    def test_wrong_metadata_identity(self):
        data, _ = oci()
        with self.assertRaises(ValueError):
            self.check(data, "sha256:" + "0" * 64)

    def test_wrong_platform(self):
        data, digest = oci(architecture="arm64")
        with self.assertRaises(ValueError):
            self.check(data, digest)

    def test_wrong_elf_or_mode(self):
        for changes in ({"elf_machine": b"\xb7\x00"}, {"mode": 0o644}):
            with self.subTest(changes=changes):
                data, digest = oci(**changes)
                with self.assertRaises(ValueError):
                    self.check(data, digest)

    def test_unreferenced_payload(self):
        data, digest = oci(extra_blob=True)
        with self.assertRaises(ValueError):
            self.check(data, digest)

    def test_uncompressed_digest(self):
        data, digest = oci(bad_diff=True)
        with self.assertRaises(ValueError):
            self.check(data, digest)

    def test_final_whiteout_removes_binary(self):
        data, digest = oci(whiteout=True)
        with self.assertRaises(ValueError):
            self.check(data, digest)

    def test_bounded_archive(self):
        data, digest = oci()
        with self.assertRaises(ValueError):
            self.check(data, digest, 32)


class ResourceTests(unittest.TestCase):
    def setUp(self):
        self.limits = {"diskFloorGiB": 20, "coldGrowthGiB": 24, "foreignGrowthGiB": 1,
                       "responseGiB": 1, "cpu": 2, "buildMemoryGiB": 6,
                       "helperMemoryMiB": 512, "pids": 512, "timeoutSeconds": 1800,
                       "logBytes": 16 * 1024**2, "metadataBytes": 16 * 1024**2,
                       "ociBytes": 512 * 1024**2, "stageArchiveBytes": 6 * GIB}
        self.sample = {"free": {"1": 46 * GIB}, "memAvailable": 9 * GIB,
                       "swapUsed": 0, "cpuCount": 2, "logBytes": 0,
                       "metadataBytes": 0, "ociBytes": 0, "stageArchiveBytes": 0, "helperGroup": {
                           "memoryMax": 512 * 1024**2, "memoryCurrent": 20 * 1024**2,
                           "swapMax": 0, "swapCurrent": 0, "pidsMax": 128, "pidsCurrent": 1,
                           "cpuMax": [200000, 100000], "oom": 0, "oomKill": 0}}

    def test_cold_admission(self):
        admission(self.sample, self.limits)

    def test_warm_budget_cannot_admit_cold_job(self):
        self.sample["free"]["1"] = 23 * GIB
        with self.assertRaises(ValueError):
            admission(self.sample, self.limits)

    def test_each_filesystem_keeps_reserve(self):
        self.sample["free"]["2"] = 40 * GIB
        with self.assertRaises(ValueError):
            admission(self.sample, self.limits)

    def test_runtime_bounds(self):
        for key, value in (("memAvailable", 2 * GIB - 1), ("swapUsed", 1),
                           ("logBytes", self.limits["logBytes"] + 1),
                           ("metadataBytes", self.limits["metadataBytes"] + 1),
                           ("ociBytes", self.limits["ociBytes"] + 1),
                           ("stageArchiveBytes", self.limits["stageArchiveBytes"] + 1)):
            sample = copy.deepcopy(self.sample)
            sample[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                resource_check(sample, self.sample, self.limits, 1)

    def test_deadline_and_changed_filesystem(self):
        with self.assertRaises(ValueError):
            resource_check(self.sample, self.sample, self.limits, 1801)
        sample = copy.deepcopy(self.sample)
        sample["free"]["extra"] = 100 * GIB
        with self.assertRaises(ValueError):
            resource_check(sample, self.sample, self.limits, 1)

    def test_cgroup_changes_and_oom_fail(self):
        group = {"memoryMax": 6 * GIB, "memoryCurrent": GIB,
                 "swapMax": 0, "swapCurrent": 0, "pidsMax": 512, "pidsCurrent": 10,
                 "cpuMax": [200000, 100000], "oom": 0, "oomKill": 0}
        sample = copy.deepcopy(self.sample)
        sample["buildGroup"] = group
        resource_check(sample, self.sample, self.limits, 1)
        for key, value in (("memoryMax", 7 * GIB), ("swapMax", 1), ("swapCurrent", 1),
                           ("pidsMax", 513), ("pidsCurrent", 513),
                           ("cpuMax", [300000, 100000]), ("oom", 1), ("oomKill", 1)):
            changed = copy.deepcopy(sample)
            changed["buildGroup"][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                resource_check(changed, self.sample, self.limits, 1)

    def test_helper_group_cannot_be_missing_or_unbounded(self):
        for changed in (None, {"memoryMax": 0}, {"pidsMax": 999}, {"swapMax": 1}):
            sample = copy.deepcopy(self.sample)
            if changed is None:
                del sample["helperGroup"]
            else:
                sample["helperGroup"].update(changed)
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                admission(sample, self.limits)

    def test_cleanup_rejects_foreign_resource(self):
        resource = {"Name": "/owned", "Config": {"Labels": {
            "io.nostr-vpn.seed-job": "job", "io.nostr-vpn.seed-source": "source"}}}
        owned_resource(resource, "owned", "job", "source")
        for name, owner, product in (("foreign", "job", "source"),
                                     ("owned", "foreign", "source"),
                                     ("owned", "job", "foreign")):
            with self.assertRaises(ValueError):
                owned_resource(resource, name, owner, product)


class CachedExportTests(unittest.TestCase):
    def test_actual_run_steps_must_be_cached(self):
        good = "#12 [bookworm-index 3/3] RUN apt-get update\n#12 CACHED\n" \
               "#19 [rust-builder 6/6] RUN cargo build --release --locked\n#19 CACHED\n"
        self.assertEqual(verify_cached_export(good), ["12", "19"])
        for bad in (good.replace("#19 CACHED", "#19 0.15     Compiling nvpn"),
                    "#1 CACHED\n", good.replace("#12 CACHED", "#12 DONE 3.0s")):
            with self.assertRaises(ValueError):
                verify_cached_export(bad)


class SourceTests(unittest.TestCase):
    def setUp(self):
        self.data = b"frozen input"
        blob = hashlib.sha1(b"blob 12\0" + self.data).hexdigest()
        rows = [{"path": "input", "mode": "100644", "blob": blob,
                 "sha256": sha256(self.data), "size": 12}]
        self.expected = {"commit": "a" * 40, "tree": "b" * 40, "sourceDateEpoch": 123,
                         "fileCount": 1, "fileBytes": 12,
                         "contextManifestSha256": sha256(canonical(rows)),
                         "files": {"input": sha256(self.data)}}
        self.answers = {("ls-files", "--others", "--ignored", "--exclude-standard"): "",
                        ("rev-parse", "HEAD"): "a" * 40,
                        ("rev-parse", "HEAD^{tree}"): "b" * 40,
                        ("log", "-1", "--format=%ct"): "123",
                        ("status", "--porcelain", "--untracked-files=all"): "",
                        ("ls-tree", "-r", "-z", "HEAD"): "100644 blob " + blob + "\tinput\0"}

    def check(self):
        outer = self
        class File:
            def lstat(self):
                return types.SimpleNamespace(st_mode=stat.S_IFREG | 0o644, st_size=len(outer.data))
            def read_bytes(self):
                return outer.data
        class Root:
            def __truediv__(self, name):
                return File()
        return verify_source(Root(), self.expected,
                             lambda root, *args: self.answers[args])

    def test_frozen_source(self):
        self.assertEqual(len(self.check()), 1)

    def test_source_tamper(self):
        self.data = b"changed input"
        with self.assertRaises(ValueError):
            self.check()

    def test_wrong_commit_tree_epoch_dirty_or_context(self):
        for key in (("ls-files", "--others", "--ignored", "--exclude-standard"),
                    ("rev-parse", "HEAD"), ("rev-parse", "HEAD^{tree}"),
                    ("log", "-1", "--format=%ct"),
                    ("status", "--porcelain", "--untracked-files=all")):
            old = self.answers[key]
            self.answers[key] = "456"
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.check()
            self.answers[key] = old
        self.expected["contextManifestSha256"] = "0" * 64
        with self.assertRaises(ValueError):
            self.check()


class ProducerTests(unittest.TestCase):
    def test_command_uses_frozen_recipe_epoch_and_never_publishes(self):
        runner = types.SimpleNamespace(buildx=Path("/tools/buildx"), name="job",
                                       pins={"product": {"sourceDateEpoch": 1793838134}})
        args = build_arguments(runner, Path("/product"), Path("/out/image.tar"),
                               Path("/out/metadata.json"))
        self.assertIn("SOURCE_DATE_EPOCH=1793838134", args)
        self.assertEqual(args[args.index("--file") + 1], "/product/umbrel/Dockerfile")
        self.assertEqual(args[-1], "/product")
        self.assertIn("type=oci,dest=/out/image.tar,rewrite-timestamp=true", args)
        self.assertNotIn("--push", args)
        self.assertNotIn("--load", args)
        self.assertFalse(any("push=true" in arg or "cache-from" in arg for arg in args))

    def cleanup_fixture(self, foreign=False, image=False):
        runner = Runner.__new__(Runner)
        runner.name, runner.owner = "job", "run"
        runner.pins = {"product": {"commit": "source"}}
        runner.limits = {"cleanupSeconds": 60}
        runner.builder_created, runner.volume_created = False, False
        runner.container = "job"
        runner.inspection_container = None
        runner.inspection_image = "job-toolchain" if image else None
        runner.inspection_image_id = "sha256:" + "a" * 64
        runner.group = None
        runner.work = types.SimpleNamespace(
            __truediv__=lambda self, name: None)
        class Absent:
            def exists(self):
                return False
        class Work:
            def __truediv__(self, name):
                return Absent()
        runner.work = Work()
        runner.save_state = lambda closed=False: None
        calls = []
        present = True
        def run(args, **kwargs):
            nonlocal present
            calls.append(args)
            if args[1:3] == ["container", "inspect"]:
                return json.dumps([{"Name": "/job", "Config": {"Labels": {
                    "io.nostr-vpn.seed-job": "foreign" if foreign else "run",
                    "io.nostr-vpn.seed-source": "source"}}}])
            if args[1:3] == ["ps", "-aq"]:
                return "id" if present else ""
            if args[1:3] == ["rm", "-f"]:
                present = False
                return "removed"
            if args[1:3] == ["image", "ls"]:
                return "sha256:" + "b" * 64
            raise AssertionError("Unexpected cleanup call: " + repr(args))
        runner.run = run
        with patch("seed_hosted_runtime.signal.setitimer"):
            receipt = runner.cleanup(Path("/tools/buildx"))
        return receipt, calls

    def test_cleanup_closes_exact_owned_container(self):
        receipt, calls = self.cleanup_fixture()
        self.assertTrue(receipt["closed"])
        self.assertIn(["docker", "rm", "-f", "job"], calls)

    def test_cleanup_failure_retains_foreign_container(self):
        receipt, calls = self.cleanup_fixture(foreign=True)
        self.assertFalse(receipt["closed"])
        self.assertFalse(any(call[1:3] == ["rm", "-f"] for call in calls))

    def test_cleanup_failure_retains_changed_image(self):
        receipt, calls = self.cleanup_fixture(image=True)
        self.assertFalse(receipt["closed"])
        self.assertFalse(any(call[1:3] == ["image", "rm"] for call in calls))


if __name__ == "__main__":
    unittest.main()
