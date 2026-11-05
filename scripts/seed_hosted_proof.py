#!/usr/bin/env python3
"""Pure, fail-closed checks for the fixed seed candidate producer."""
import hashlib
import json
import os
import re
import stat
from pathlib import Path

GIB = 1024**3
MIB = 1024**2


def require(ok, message):
    if not ok:
        raise ValueError(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def integer(value, name, minimum=0):
    require(type(value) is int and value >= minimum, "Invalid " + name)
    return value


def resource_check(sample, initial, limits, elapsed):
    """All bytes are actual filesystem/cgroup observations, not reclaimable RAM."""
    floor = integer(limits["diskFloorGiB"], "floor", 1) * GIB
    own = integer(limits["coldGrowthGiB"], "growth", 1) * GIB
    foreign = integer(limits["foreignGrowthGiB"], "foreign", 1) * GIB
    response = integer(limits["responseGiB"], "response", 1) * GIB
    require(sample["free"].keys() == initial["free"].keys(), "Filesystem set changed")
    for device, free in sample["free"].items():
        integer(free, "free")
        require(free >= floor + response, "Physical reserve breached")
        require(initial["free"][device] - free <= own + foreign, "Disk growth exceeded")
    require(integer(sample["memAvailable"], "MemAvailable") >= 2 * GIB,
            "Host memory response reserve breached")
    require(integer(sample["swapUsed"], "swap") <= initial["swapUsed"],
            "Host reported swap usage increased")
    require(elapsed <= limits["timeoutSeconds"], "Producer deadline exceeded")
    require(sample["logBytes"] <= limits["logBytes"], "Log bound exceeded")
    require(sample["metadataBytes"] <= limits["metadataBytes"], "Metadata bound exceeded")
    require(sample["ociBytes"] <= limits["ociBytes"], "OCI output bound exceeded")
    require(sample["stageArchiveBytes"] <= limits["stageArchiveBytes"],
            "Inspection stage output bound exceeded")
    for name, memory, pids in (("buildGroup", limits["buildMemoryGiB"] * GIB, limits["pids"]),
                               ("helperGroup", limits["helperMemoryMiB"] * MIB, 128)):
        group = sample.get(name)
        require(name != "helperGroup" or group is not None, "Helper cgroup missing")
        if group is None:
            continue
        require(group["memoryMax"] == memory, "Cgroup memory limit changed")
        require(group["swapMax"] == 0 and group["swapCurrent"] == 0,
                "Build cgroup swap is not disabled")
        require(group["pidsMax"] == pids and
                group["pidsCurrent"] <= pids, "Build PID limit changed")
        require(group["cpuMax"] == [limits["cpu"] * 100000, 100000],
                "Build CPU quota changed")
        require(group["oom"] == 0 and group["oomKill"] == 0, "Build cgroup OOM event")
        require(group["memoryCurrent"] <= group["memoryMax"], "Build memory exceeded")


def admission(sample, limits):
    required = sum(limits[x] for x in
                   ("diskFloorGiB", "coldGrowthGiB", "foreignGrowthGiB", "responseGiB")) * GIB
    require(sample["free"] and all(type(n) is int and n >= required
                                  for n in sample["free"].values()),
            "Hosted cold-build disk admission failed")
    require(sample["memAvailable"] >=
            limits["buildMemoryGiB"] * GIB + limits["helperMemoryMiB"] * MIB + 2 * GIB,
            "Hosted cold-build memory admission failed")
    require(sample["cpuCount"] >= limits["cpu"], "Insufficient admitted CPUs")
    resource_check(sample, sample, limits, 0)


def verify_source(root, expected, git):
    require(git(root, "rev-parse", "HEAD").strip() == expected["commit"],
            "Product commit mismatch")
    require(git(root, "rev-parse", "HEAD^{tree}").strip() == expected["tree"],
            "Product tree mismatch")
    require(int(git(root, "log", "-1", "--format=%ct").strip()) ==
            expected["sourceDateEpoch"], "Product epoch mismatch")
    require(not git(root, "status", "--porcelain", "--untracked-files=all").strip(),
            "Product checkout is not clean")
    require(not git(root, "ls-files", "--others", "--ignored", "--exclude-standard").strip(),
            "Ignored files would change the product build context")
    rows = []
    total = 0
    for record in git(root, "ls-tree", "-r", "-z", "HEAD").split("\0"):
        if not record:
            continue
        header, name = record.split("\t", 1)
        mode, kind, blob = header.split()
        require(kind == "blob" and mode in ("100644", "100755"),
                "Unsupported product tree entry")
        require(not name.startswith("/") and ".." not in Path(name).parts,
                "Invalid product path")
        path = root / name
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode), "Nonregular product file")
        require(bool(info.st_mode & 0o111) == (mode == "100755"),
                "Product executable mode mismatch")
        require(0 <= info.st_size <= expected["fileBytes"] - total and
                len(rows) < expected["fileCount"], "Product file extent exceeded")
        data = path.read_bytes()
        require(len(data) == info.st_size, "Product file changed while reading")
        total += len(data)
        require(hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
                == blob, "Product blob mismatch")
        rows.append({"path": name, "mode": mode, "blob": blob,
                     "sha256": sha256(data), "size": len(data)})
    require(len(rows) == expected["fileCount"] and
            sum(row["size"] for row in rows) == expected["fileBytes"],
            "Product context extent mismatch")
    require(sha256(canonical(rows)) == expected["contextManifestSha256"],
            "Product context manifest mismatch")
    by_path = {row["path"]: row["sha256"] for row in rows}
    require(all(by_path.get(name) == digest for name, digest in expected["files"].items()),
            "Product recipe/lock binding mismatch")
    return rows


def verify_toolchain(text, expected):
    require(len(text.encode()) <= 65536, "Toolchain evidence is too large")
    sections = {}
    current = None
    for line in text.splitlines():
        if line.startswith("==") and line.endswith("=="):
            current = line[2:-2]
            require(current not in sections, "Duplicate toolchain section")
            sections[current] = []
        else:
            require(current is not None, "Unframed toolchain output")
            sections[current].append(line)
    require(set(sections) == {"rustc", "cargo", "gcc", "os", "packages"},
            "Missing toolchain evidence")
    rust = "\n".join(sections["rustc"])
    require(re.search(r"^release: " + re.escape(expected["rustRelease"]) + r"$",
                      rust, re.M) is not None, "Rust release mismatch")
    require(re.search(r"^commit-hash: " + re.escape(expected["rustCommitPrefix"]) +
                      r"[0-9a-f]+$", rust, re.M) is not None, "Rust source mismatch")
    require(re.search(r"^LLVM version: " + re.escape(expected["llvm"]) + r"$",
                      rust, re.M) is not None, "Rust LLVM mismatch")
    require(re.fullmatch(r"cargo " + re.escape(expected["cargo"]) + r" \([^\n]+\)",
                         "\n".join(sections["cargo"])) is not None, "Cargo mismatch")
    require(sections["gcc"] == [expected["gcc"]], "GCC mismatch")
    require('VERSION_CODENAME=' + expected["debian"] in sections["os"],
            "Builder OS mismatch")
    require(sections["packages"] and all(re.fullmatch(r"[\w.+:-]+\t[^\t\n]+", row)
                                       for row in sections["packages"]),
            "Missing realized package versions")
    return sections


def owned_resource(inspect, name, owner, product):
    require(inspect.get("Name", "").lstrip("/") == name, "Resource name mismatch")
    labels = inspect.get("Labels", inspect.get("Config", {}).get("Labels", {}))
    require(labels.get("io.nostr-vpn.seed-job") == owner and
            labels.get("io.nostr-vpn.seed-source") == product,
            "Resource ownership mismatch")


def initial_apt_504(log):
    """Recognize only the frozen rust-builder package install's complete 504 failure."""
    command = ('process "/bin/sh -c apt-get -c /snapshot/apt.conf install -y '
               '--no-install-recommends       clang       libclang-dev       '
               'libdbus-1-dev       pkg-config     && rm -rf /var/lib/apt/lists/*" '
               'did not complete successfully: exit code: 100')
    lines = log.splitlines()
    final = "ERROR: failed to build: failed to solve: " + command
    if not lines or lines[-1] != final or [l for l in lines if l.startswith("ERROR:")] != [final]:
        return False
    if any(re.match(r"#\d+ CANCELED(?:\s|$)", line) for line in lines):
        return False
    failures = [l for l in lines if re.match(r"#\d+ ERROR:", l)]
    if len(failures) != 1:
        return False
    failure = re.fullmatch(r"#(\d+) ERROR: " + re.escape(command), failures[0])
    if failure is None:
        return False
    errors = [m.groups() for l in lines
              if (m := re.fullmatch(r"#(\d+) [0-9]+\.[0-9]+ (E: .+)", l))]
    if len(errors) < 2 or any(step != failure[1] for step, _ in errors):
        return False
    if errors[-1][1] != "E: Unable to fetch some archives, maybe run apt-get update or try with --fix-missing?":
        return False
    package_504 = (r"E: Failed to fetch https://snapshot\.debian\.org/archive/debian/"
                   r"20261027T000000Z/pool/[A-Za-z0-9_./%+~:-]+\.deb  "
                   r"504  Gateway Timeout \[IP: [0-9a-fA-F:.]+ 443\]")
    return all(re.fullmatch(package_504, message) for _, message in errors[:-1])


class CachedRunGuard:
    """Consume BuildKit v0.34.2 SolveStatus rawjson while the export is running."""
    def __init__(self):
        self.pending = bytearray()
        self.vertices = {}
        self.runs = set()
        self.completed = set()

    def feed(self, data):
        self.pending.extend(data)
        require(len(self.pending) <= 256 * 1024, "Raw progress line exceeded bound")
        while b"\n" in self.pending:
            line, _, remaining = self.pending.partition(b"\n")
            self.pending = bytearray(remaining)
            require(line, "Empty raw progress event")
            event = json.loads(line)
            require(isinstance(event, dict), "Invalid raw progress event")
            vertices = event.get("vertexes", [])
            require(isinstance(vertices, list) and len(vertices) <= 2048,
                    "Invalid progress vertices")
            for vertex in vertices:
                require(isinstance(vertex, dict), "Invalid progress vertex")
                identity = vertex.get("digest", "")
                require(re.fullmatch(r"sha256:[0-9a-f]{64}", identity), "Invalid vertex identity")
                previous = self.vertices.get(identity, {})
                if "name" in vertex:
                    require(isinstance(vertex["name"], str) and
                            ("name" not in previous or previous["name"] == vertex["name"]),
                            "Progress vertex name changed")
                merged = {**previous, **vertex}
                self.vertices[identity] = merged
                require(len(self.vertices) <= 2048, "Progress vertex bound exceeded")
                name = merged.get("name", "")
                if re.search(r"\] RUN ", name):
                    self.runs.add(identity)
                    # Cached completion is explicitly marked in the same Vertex update.
                    # Never wait for a RUN to complete before rejecting an actual start.
                    if vertex.get("started") or vertex.get("completed"):
                        require(vertex.get("cached") is True,
                                "Uncached RUN started during cache-only export")
                    if vertex.get("cached") is True and vertex.get("completed"):
                        self.completed.add(identity)
            require(not event.get("logs"), "Execution logs in cache-only export")

    def finish(self):
        require(not self.pending, "Truncated raw progress event")
        require(self.runs and self.runs == self.completed, "Incomplete cached RUN proof")
        return sorted(self.runs)


def verify_cached_export(text):
    guard = CachedRunGuard()
    guard.feed(text.encode())
    return guard.finish()
