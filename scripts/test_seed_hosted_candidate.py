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
import os
import sys
import subprocess
import time
import tempfile
from unittest.mock import patch
from pathlib import Path

from seed_hosted_candidate import build_arguments, initial_solve, inspect_realized_builder
from seed_hosted_runtime import (CommandFailure, Runner, container_group, directory_identity,
                                  group_sample, process_identity)

from seed_hosted_proof import (CachedRunGuard, GIB, admission, canonical, initial_apt_504, owned_resource,
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


def raw_vertex(number, name, cached=None, started=False, completed=False):
    row = {"digest": "sha256:" + format(number, "064x"), "name": name}
    if cached is not None:
        row["cached"] = cached
    if started:
        row["started"] = "2026-11-05T00:00:00Z"
    if completed:
        row["completed"] = "2026-11-05T00:00:00Z"
    return canonical({"vertexes": [row]}) + b"\n"


class CachedExportTests(unittest.TestCase):
    def test_actual_run_steps_must_be_cached(self):
        good = raw_vertex(12, "[bookworm-index 3/3] RUN apt-get update", True, True, True) + \
               raw_vertex(19, "[rust-builder 6/6] RUN cargo build", True, True, True)
        self.assertEqual(verify_cached_export(good.decode()),
                         ["sha256:" + format(n, "064x") for n in (12, 19)])
        for bad in (raw_vertex(19, "[rust-builder 6/6] RUN cargo build", False, True),
                    raw_vertex(1, "exporting to image", True, True, True),
                    raw_vertex(19, "[rust-builder 6/6] RUN cargo build", True, True)):
            with self.assertRaises(ValueError):
                verify_cached_export(bad.decode())

    def test_fragmented_updates_reject_uncached_start_before_completion(self):
        guard = CachedRunGuard()
        scheduled = raw_vertex(19, "[rust-builder 6/6] RUN cargo build")
        for byte in scheduled:
            guard.feed(bytes([byte]))
        started = canonical({"vertexes": [{"digest": "sha256:" + format(19, "064x"),
                                           "started": "2026-11-05T00:00:00Z"}]}) + b"\n"
        with self.assertRaisesRegex(ValueError, "Uncached RUN started"):
            guard.feed(started)

    def test_progress_bounds_and_execution_logs_fail_closed(self):
        for data in (b"x" * (256 * 1024 + 1), b"not json\n",
                     canonical({"logs": [{"data": "RUN output"}]}) + b"\n"):
            with self.subTest(length=len(data)), self.assertRaises(ValueError):
                CachedRunGuard().feed(data)

    def test_actual_process_is_cancelled_before_delayed_completion(self):
        runner = Runner.__new__(Runner)
        runner.started = time.monotonic()
        runner.limits = {"timeoutSeconds": 10, "logBytes": 1024 * 1024}
        runner.environment = {"PATH": "/usr/bin:/bin"}
        runner.check = lambda: None
        stopped = []
        runner.stop_builder = lambda: stopped.append(time.monotonic())
        class LogPath:
            def __truediv__(self, name):
                return self
            def open(self, mode):
                return io.BytesIO()
        runner.output = LogPath()
        row = raw_vertex(19, "[rust-builder 6/6] RUN cargo build", False, True)
        program = "import sys,time;sys.stdout.buffer.write(" + repr(row) + \
                  ");sys.stdout.flush();time.sleep(10)"
        processes = []
        original = subprocess.Popen
        def launch(*args, **kwargs):
            process = original(*args, **kwargs)
            processes.append(process)
            return process
        before = time.monotonic()
        with patch("seed_hosted_runtime.subprocess.Popen", side_effect=launch):
            with self.assertRaisesRegex(ValueError, "Uncached RUN started"):
                runner.run([sys.executable, "-c", program], timeout=10,
                           progress_guard=CachedRunGuard())
        self.assertLess(time.monotonic() - before, 2)
        self.assertEqual(len(stopped), 1)
        self.assertEqual(len(processes), 1)
        self.assertIsNotNone(processes[0].poll())


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


def apt_failure():
    # Pinned Buildx/BuildKit plain-progress shape, with a documentation-only IP.
    command = ('process "/bin/sh -c apt-get -c /snapshot/apt.conf install -y '
               '--no-install-recommends       clang       libclang-dev       '
               'libdbus-1-dev       pkg-config     && rm -rf /var/lib/apt/lists/*" '
               'did not complete successfully: exit code: 100')
    return ("#19 127.1 E: Failed to fetch https://snapshot.debian.org/archive/debian/"
            "20261027T000000Z/pool/main/d/dbus/libdbus-1-dev_1.14.10-1%7edeb12u1_amd64.deb  "
            "504  Gateway Timeout [IP: 192.0.2.1 443]\n"
            "#19 127.1 E: Unable to fetch some archives, maybe run apt-get update or try with --fix-missing?\n"
            "#19 ERROR: " + command + "\nERROR: failed to build: failed to solve: " + command + "\n")


class InitialSolveTests(unittest.TestCase):
    def test_only_complete_pinned_package_504(self):
        good = apt_failure()
        self.assertTrue(initial_apt_504(good))
        second = good.splitlines()[0].replace("libdbus-1-dev", "clang-14") + "\n"
        self.assertTrue(initial_apt_504(second + good))
        for bad in (good.replace("504", "503"), good.replace("Gateway Timeout", "Hash Sum mismatch"),
                    good.replace("20261027", "20261028"), good.replace("https://", "http://"),
                    good.replace("snapshot.debian.org", "mirror.example"),
                    good.replace("exit code: 100", "exit code: 137"),
                    good.replace("install -y", "update -y"),
                    good.replace("#19 127.1 E:", "#20 127.1 E:", 1),
                    good.replace("#19 ERROR:", "#20 ERROR:"),
                    good.replace(" 443]", " 80]"), good.replace(".deb  504", ".deb  404", 1),
                    good.rsplit("\nERROR:", 1)[0], good + "unexpected failure\n",
                    "#20 ERROR: compilation failed\n" + good,
                    "#20 CANCELED\n" + good,
                    "#20 CANCELED context canceled\n" + good,
                    "ERROR: unrelated failure\n" + good,
                    "#19 127.1 E: Invalid signature\n" + good,
                    second.replace("504", "404") + good):
            with self.subTest(log=bad):
                self.assertFalse(initial_apt_504(bad))

    def run_solve(self, failures, artifact=None, guard_failure=None, prefix=""):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            log = root / "producer.log"
            log.write_text(prefix)
            candidate, metadata = root / "image.tar", root / "metadata.json"
            if artifact:
                {"candidate": candidate, "metadata": metadata}[artifact].touch()
            self.calls, self.checks, self.evidence = [], [], []
            def check(force=False):
                self.checks.append(force)
                if guard_failure == len(self.checks):
                    raise ValueError("Resource or deadline limit")
            def run(arguments, **kwargs):
                self.calls.append((list(arguments), kwargs))
                item = failures[len(self.calls) - 1]
                if item:
                    with log.open("a") as output:
                        output.write(apt_failure())
                    raise item
            runner = types.SimpleNamespace(
                buildx=Path("/tools/buildx"), name="same-builder", output=root,
                pins={"product": {"sourceDateEpoch": 1793838134}},
                limits={"timeoutSeconds": 1800, "logBytes": 1024 * 1024}, check=check, run=run)
            initial_solve(runner, Path("/product"), candidate, metadata, self.evidence)

    def test_retry_once_same_arguments_and_preserve_first_failure(self):
        self.run_solve([CommandFailure("buildx", 1), None], prefix="unrelated prior command\n")
        self.assertEqual(len(self.calls), 2)
        self.assertEqual(self.calls[0], self.calls[1])
        self.assertEqual(self.checks, [True, True, True])
        self.assertEqual(self.evidence[0]["logSha256"], sha256(apt_failure().encode()))
        self.assertFalse(self.evidence[0]["accepted"])
        self.assertIn("retryReason", self.evidence[0])
        self.assertTrue(self.evidence[1]["accepted"])

    def test_success_never_retried(self):
        self.run_solve([None])
        self.assertEqual(len(self.calls), 1)

    def test_second_504_is_terminal(self):
        with self.assertRaises(CommandFailure):
            self.run_solve([CommandFailure("buildx", 1), CommandFailure("buildx", 1)])
        self.assertEqual(len(self.calls), 2)
        self.assertNotIn("retryReason", self.evidence[1])

    def test_resource_deadline_signal_unknown_error_or_outputs_never_retry(self):
        for error in (CommandFailure("buildx", -15), CommandFailure("buildx", 2),
                      ValueError("log bound"), TimeoutError("deadline")):
            with self.subTest(error=repr(error)), self.assertRaises(type(error)):
                self.run_solve([error])
            self.assertEqual(len(self.calls), 1)
        for artifact in ("candidate", "metadata"):
            with self.subTest(artifact=artifact), self.assertRaises(CommandFailure):
                self.run_solve([CommandFailure("buildx", 1)], artifact=artifact)
            self.assertEqual(len(self.calls), 1)
        for check_number in (2, 3):
            with self.subTest(check=check_number), self.assertRaisesRegex(ValueError, "Resource"):
                self.run_solve([CommandFailure("buildx", 1)], guard_failure=check_number)
            self.assertEqual(len(self.calls), 1)


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

    def test_inspection_only_starts_after_verified_builder_closure(self):
        for close in (True, False):
            with self.subTest(close=close):
                events = []
                class FilePath:
                    def __init__(self, value):
                        self.value = value
                    def __truediv__(self, name):
                        return FilePath(self.value + "/" + name)
                    def __str__(self):
                        return self.value
                    def read_text(self):
                        return json.dumps({"containerimage.config.digest": "sha256:" + "a" * 64})
                runner = types.SimpleNamespace(
                    work=FilePath("/work"), output=FilePath("/out"), buildx=Path("/tools/buildx"),
                    name="job", owner="owner", container="job", group="active",
                    pins={"product": {"sourceDateEpoch": 1793838134, "commit": "source"},
                          "toolchain": {}}, save_state=lambda: None,
                    check=lambda **kwargs: events.append("check"),
                    inspect=lambda *args: {"Id": "sha256:" + "a" * 64})
                def stop():
                    events.append("builder-closed" if close else "builder-not-closed")
                    if close:
                        runner.container, runner.group = None, None
                    return {"closed": close}
                runner.stop_builder = stop
                def run(args, **kwargs):
                    if "progress_guard" in kwargs:
                        self.assertIn("rawjson", args)
                        kwargs["progress_guard"].feed(raw_vertex(
                            19, "[rust-builder 6/6] RUN cargo build", True, True, True))
                    if args[:2] == ["docker", "run"]:
                        self.assertIsNone(runner.container)
                        self.assertIsNone(runner.group)
                        self.assertIn("--memory=256m", args)
                        self.assertIn("--memory-swap=256m", args)
                        self.assertIn("--pids-limit=32", args)
                        events.append("inspection")
                    return ""
                runner.run = run
                with patch("seed_hosted_candidate.verify_toolchain", return_value={}):
                    if close:
                        result = inspect_realized_builder(runner, Path("/product"))
                        self.assertTrue(result["builderClosureBeforeInspection"]["closed"])
                        self.assertLess(events.index("builder-closed"), events.index("inspection"))
                    else:
                        with self.assertRaises(ValueError):
                            inspect_realized_builder(runner, Path("/product"))
                        self.assertNotIn("inspection", events)

    def test_populated_builder_cgroup_prevents_scope_release(self):
        runner = Runner.__new__(Runner)
        runner.container = runner.name = "job"
        runner.owner = "owner"
        runner.pins = {"product": {"commit": "source"}}
        runner.run = lambda *args, **kwargs: ""
        runner.inspect = lambda *args, **kwargs: {"Name": "/job", "Config": {"Labels": {
            "io.nostr-vpn.seed-job": "owner", "io.nostr-vpn.seed-source": "source"}}}
        runner.save_state = lambda: None
        class Group:
            def exists(self):
                return True
            def __truediv__(self, name):
                return types.SimpleNamespace(read_text=lambda: "populated 1\n" if
                                             name == "cgroup.events" else "1")
        runner.group = Group()
        runner.group_binding = (1, 2)
        runner.group.lstat = lambda: types.SimpleNamespace(
            st_mode=stat.S_IFDIR | 0o755, st_dev=1, st_ino=2)
        with self.assertRaisesRegex(ValueError, "still has processes"):
            runner.stop_builder()
        self.assertEqual(runner.container, "job")

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


class CgroupBindingTests(unittest.TestCase):
    def test_exact_systemd_container_and_init_use_same_aggregate_scope(self):
        identity = "a" * 64
        root = Path("/sys/fs/cgroup/system.slice/docker-" + identity + ".scope")
        self.assertEqual(container_group(root, identity), root)
        self.assertEqual(container_group(root / "init", identity), root)

    def test_exact_cgroupfs_container_and_init_use_same_aggregate_scope(self):
        identity = "a" * 64
        root = Path("/sys/fs/cgroup/docker") / identity
        self.assertEqual(container_group(root / "init", identity), root)

    def test_no_arbitrary_ancestor_or_unexpected_descendant(self):
        identity = "a" * 64
        root = Path("/sys/fs/cgroup/docker") / identity
        invalid = (
            root / "other", root / "init" / "nested", root / identity,
            Path("/sys/fs/cgroup/system.slice/other.scope/init"),
            Path("/sys/fs/cgroup"), Path("/tmp") / identity,
            root / ".." / identity,
        )
        for path in invalid:
            with self.subTest(path=str(path)), self.assertRaises(ValueError):
                container_group(path, identity)
        with self.assertRaises(ValueError):
            container_group(root, identity[:12])

    def test_pid_identity_parses_comm_with_spaces_and_parenthesis(self):
        value = "123 (buildkit ) daemon) S " + "0 " * 18 + "456 0 0\n"
        with patch("seed_hosted_runtime.Path.read_text", return_value=value):
            self.assertEqual(process_identity(123), 456)
        for bad in (value.replace("123 (", "124 ("), value.replace("456", "max"), "123 short"):
            with patch("seed_hosted_runtime.Path.read_text", return_value=bad):
                with self.assertRaises(ValueError):
                    process_identity(123)
        with self.assertRaises(ValueError):
            process_identity(True)

    def test_binding_rejects_symlink(self):
        path = types.SimpleNamespace(lstat=lambda: types.SimpleNamespace(
            st_mode=stat.S_IFLNK | 0o777, st_dev=1, st_ino=2))
        with self.assertRaises(ValueError):
            directory_identity(path)

    def test_unbounded_selected_scope_is_still_rejected(self):
        class Group:
            def __truediv__(self, name):
                value = "oom 0\noom_kill 0\n" if name == "memory.events" else "max"
                return types.SimpleNamespace(read_text=lambda: value)
        with self.assertRaisesRegex(ValueError, "memory.max"):
            group_sample(Group())

    def test_parent_aggregate_is_sampled_when_init_limits_are_inherited(self):
        identity = "a" * 64
        root = Path("/sys/fs/cgroup/system.slice/docker-" + identity + ".scope")
        leaf = root / "init"
        values = {"memory.events": "oom 0\noom_kill 0\n", "memory.max": str(6 * GIB),
                  "memory.current": "123456", "memory.swap.max": "0",
                  "memory.swap.current": "0", "pids.max": "512", "pids.current": "9",
                  "cpu.max": "200000 100000"}
        def read(path):
            if path.parent == leaf and path.name.endswith(".max"):
                return "max"
            return values[path.name]
        runner = Runner.__new__(Runner)
        runner.work = Path("/nonexistent")
        runner.filesystems = {}
        runner.helper_group = Path("/sys/fs/cgroup/helper")
        runner.group = container_group(leaf, identity)
        runner.group_binding = (1, 2)
        runner.builder_process = (123, 456, identity)
        with patch("seed_hosted_runtime.meminfo", return_value=(9 * GIB, 0)), \
                patch("seed_hosted_runtime.os.sched_getaffinity", return_value={0, 1}, create=True), \
                patch("seed_hosted_runtime.directory_identity", return_value=(1, 2)), \
                patch("seed_hosted_runtime.process_identity", return_value=456), \
                patch("seed_hosted_runtime.process_group", return_value=leaf), \
                patch("seed_hosted_runtime.Path.read_text", autospec=True, side_effect=read):
            with self.assertRaisesRegex(ValueError, "memory.max"):
                group_sample(leaf)
            sample = runner.sample()
        self.assertEqual(sample["buildPidCgroup"], str(leaf))
        self.assertEqual(sample["buildGroup"]["memoryMax"], 6 * GIB)
        self.assertEqual(sample["buildGroup"]["memoryCurrent"], 123456)
        self.assertEqual(sample["buildGroup"]["pidsCurrent"], 9)

    def test_cgroup_scope_replacement_fails_before_sampling(self):
        runner = Runner.__new__(Runner)
        runner.work = Path("/nonexistent")
        runner.filesystems = {}
        runner.helper_group = "helper"
        runner.group = types.SimpleNamespace(lstat=lambda: types.SimpleNamespace(
            st_mode=stat.S_IFDIR | 0o755, st_dev=1, st_ino=99))
        runner.group_binding = (1, 2)
        with patch("seed_hosted_runtime.meminfo", return_value=(9 * GIB, 0)), \
                patch("seed_hosted_runtime.os.sched_getaffinity", return_value={0, 1}, create=True), \
                patch("seed_hosted_runtime.group_sample", return_value={}):
            with self.assertRaisesRegex(ValueError, "directory identity changed"):
                runner.sample()


class SampleCadenceTests(unittest.TestCase):
    setUp = ResourceTests.setUp

    def runner(self):
        runner = Runner.__new__(Runner)
        runner.cancelled = False
        runner.started = 10.0
        runner.last_sample_at = None
        runner.samples = []
        runner.limits = self.limits
        runner.initial = copy.deepcopy(self.sample)
        runner.sample = lambda: copy.deepcopy(self.sample)
        return runner

    def test_bulk_chunks_are_one_global_sample_per_second(self):
        runner = self.runner()
        with patch("seed_hosted_runtime.time.monotonic", return_value=10.0):
            for _ in range(1078):
                runner.check()
        self.assertEqual(len(runner.samples), 1)
        with patch("seed_hosted_runtime.time.monotonic", return_value=10.999):
            runner.check()
        self.assertEqual(len(runner.samples), 1)
        with patch("seed_hosted_runtime.time.monotonic", return_value=11.0):
            runner.check()
        self.assertEqual(len(runner.samples), 2)
        self.assertEqual(runner.samples[-1]["elapsedSeconds"], 1.0)

    def test_cancellation_and_deadline_are_never_throttled(self):
        runner = self.runner()
        runner.last_sample_at = 10.0
        runner.cancelled = True
        with patch("seed_hosted_runtime.time.monotonic", return_value=10.001):
            with self.assertRaisesRegex(ValueError, "cancellation"):
                runner.check()
        runner.cancelled = False
        runner.started = -2000.0
        with patch("seed_hosted_runtime.time.monotonic", return_value=10.001):
            with self.assertRaisesRegex(ValueError, "deadline"):
                runner.check()
        self.assertEqual(runner.samples, [])

    def test_phase_transition_forces_guard_inside_cadence(self):
        runner = self.runner()
        runner.last_sample_at = 10.0
        self.sample["swapUsed"] = 1
        with patch("seed_hosted_runtime.time.monotonic", return_value=10.001):
            with self.assertRaisesRegex(ValueError, "swap"):
                runner.check(force=True)

    def test_whole_deadline_cadence_fits_existing_evidence_bound(self):
        runner = self.runner()
        for second in range(1801):
            with patch("seed_hosted_runtime.time.monotonic", return_value=10.0 + second):
                for _ in range(3):
                    runner.check()
        self.assertEqual(len(runner.samples), 1801)
        self.assertLessEqual(len(runner.samples), self.limits["timeoutSeconds"] * 2)


if __name__ == "__main__":
    unittest.main()
