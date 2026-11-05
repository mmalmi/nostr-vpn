#!/usr/bin/env python3
"""One owned hosted build, bounded commands, and exact-resource cleanup."""
import json
import os
import re
import stat
import selectors
import signal
import subprocess
import time
from pathlib import Path

from seed_hosted_proof import GIB, admission, owned_resource, require, resource_check


PROBE_ENV = {"PATH": "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
             "HOME": "/nonexistent", "DOCKER_CONFIG": "/nonexistent",
             "DOCKER_HOST": "unix:///var/run/docker.sock", "LC_ALL": "C.UTF-8"}


def capture(arguments, timeout=15):
    result = subprocess.run(arguments, check=True, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=timeout, text=True, env=PROBE_ENV)
    require(len(result.stdout) + len(result.stderr) <= 1024 * 1024,
            "Probe output exceeded bound")
    return result.stdout


def physical_free(path):
    value = os.statvfs(path)
    return value.f_bavail * value.f_frsize


def meminfo():
    rows = {}
    for line in Path("/proc/meminfo").read_text().splitlines():
        key, value = line.split(":", 1)
        if key in ("MemAvailable", "SwapTotal", "SwapFree"):
            require(key not in rows, "Duplicate memory counter")
            words = value.split()
            require(len(words) == 2 and words[1] == "kB" and words[0].isdigit(),
                    "Invalid memory counter")
            rows[key] = int(words[0]) * 1024
    require(set(rows) == {"MemAvailable", "SwapTotal", "SwapFree"} and
            rows["SwapTotal"] >= rows["SwapFree"], "Missing memory counters")
    return rows["MemAvailable"], rows["SwapTotal"] - rows["SwapFree"]


def process_group(pid):
    paths = Path("/proc/" + str(pid) + "/cgroup").read_text().splitlines()
    require(len(paths) == 1 and paths[0].startswith("0::/"), "Unified cgroup required")
    path = (Path("/sys/fs/cgroup") / paths[0][4:]).resolve()
    require(path.is_relative_to(Path("/sys/fs/cgroup")), "Invalid cgroup path")
    return path


def process_identity(pid):
    require(type(pid) is int and pid > 0, "Invalid builder PID")
    value = Path("/proc/" + str(pid) + "/stat").read_text()
    require(value.startswith(str(pid) + " (") and ")" in value, "Invalid process identity")
    fields = value.rsplit(")", 1)[1].split()
    require(len(fields) >= 20 and re.fullmatch(r"[0-9]+", fields[19]),
            "Missing process start time")
    return int(fields[19])


def container_group(leaf, container_id):
    """Bind only Docker's exact container scope or pinned BuildKit's /init child.

    BuildKit 8c579433 executor/resources/monitor.go moves root processes into init;
    inherited limits and aggregate descendant counters remain at the container scope.
    Never climb until an unrelated ancestor happens to have matching numeric limits.
    """
    root = Path("/sys/fs/cgroup")
    require(isinstance(container_id, str) and re.fullmatch(r"[0-9a-f]{64}", container_id),
            "Invalid full container ID")
    require(leaf.is_absolute() and leaf.is_relative_to(root) and
            not any(p in (".", "..") for p in leaf.parts), "Invalid container cgroup path")
    parts = leaf.relative_to(root).parts
    names = {container_id, "docker-" + container_id + ".scope"}
    indexes = [i for i, name in enumerate(parts) if name in names]
    require(len(indexes) == 1, "Container cgroup identity is ambiguous or absent")
    index = indexes[0]
    require(parts[index + 1:] in ((), ("init",)), "Unexpected builder cgroup descendant")
    return root.joinpath(*parts[:index + 1])


def directory_identity(path):
    value = path.lstat()
    require(stat.S_ISDIR(value.st_mode), "Cgroup scope is not a real directory")
    return (value.st_dev, value.st_ino)


def group_sample(path):
    def number(name):
        value = (path / name).read_text().strip()
        require(re.fullmatch(r"[0-9]+", value), "Invalid cgroup counter: " + name)
        return int(value)
    events = dict(line.split() for line in (path / "memory.events").read_text().splitlines())
    return {"memoryMax": number("memory.max"), "memoryCurrent": number("memory.current"),
            "swapMax": number("memory.swap.max"), "swapCurrent": number("memory.swap.current"),
            "pidsMax": number("pids.max"), "pidsCurrent": number("pids.current"),
            "cpuMax": [int(x) for x in (path / "cpu.max").read_text().split()],
            "oom": int(events["oom"]), "oomKill": int(events["oom_kill"])}


class Runner:
    def __init__(self, work, pins, identity):
        self.work = work
        self.pins = pins
        self.limits = pins["limits"]
        self.identity = identity
        self.owner = identity["runId"] + "-" + identity["runAttempt"]
        self.name = "nvpn-seed-" + self.owner
        self.container = None
        self.group = None
        self.group_binding = None
        self.builder_process = None
        self.cgroup_proof = None
        self.helper_group = process_group(os.getpid())
        self.inspection_container = None
        self.inspection_image = None
        self.inspection_image_id = None
        self.volume_created = False
        self.builder_created = False
        self.started = time.monotonic()
        self.cancelled = False
        self.samples = []
        self.last_sample_at = None
        self.buildx = work / "tools" / "buildx"
        self.output = work / "output"
        self.output.mkdir()
        for name in ("home", "docker", "buildx", "tools"):
            (work / name).mkdir()
        (work / "docker" / "config.json").write_text("{}\n")
        self.environment = {
            "PATH": "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
            "HOME": str(work / "home"), "DOCKER_CONFIG": str(work / "docker"),
            "DOCKER_HOST": "unix:///var/run/docker.sock",
            "BUILDX_CONFIG": str(work / "buildx"), "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
            "TZ": "UTC", "BUILDX_METADATA_PROVENANCE": "max",
            "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_OPTIONAL_LOCKS": "0",
        }
        root = Path(json.loads(capture(["docker", "info", "--format", "{{json .DockerRootDir}}"])))
        self.filesystems = {}
        for path in (work, root):
            require(path.is_absolute() and path.exists(), "Missing output/cache filesystem")
            self.filesystems[str(path.stat().st_dev)] = path
        self.save_state()
        self.initial = self.sample()
        admission(self.initial, self.limits)
        for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            signal.signal(sig, self.stop)
        signal.signal(signal.SIGALRM, self.expired)
        signal.setitimer(signal.ITIMER_REAL, self.limits["timeoutSeconds"])

    def save_state(self, closed=False):
        state = {"owner": self.owner, "name": self.name, "identity": self.identity,
                 "product": self.pins["product"]["commit"], "container": self.container,
                 "inspectionContainer": self.inspection_container,
                 "inspectionImage": self.inspection_image, "inspectionImageId": self.inspection_image_id,
                 "volumeCreated": self.volume_created,
                 "builderCreated": self.builder_created,
                 "builderCgroup": getattr(self, "cgroup_proof", None),
                 "closed": closed}
        temporary = self.work / "owned-resources.next"
        temporary.write_text(json.dumps(state, sort_keys=True) + "\n")
        temporary.replace(self.work / "owned-resources.json")

    def expired(self, _signal, _frame):
        self.cancelled = True
        raise TimeoutError("Producer deadline exceeded")

    def stop(self, _signal, _frame):
        self.cancelled = True

    def sample(self):
        memory, swap = meminfo()
        output = self.work / "output"
        def size(name):
            path = self.work / name
            return path.stat().st_size if path.exists() else 0
        metadata = sum(p.stat().st_size for p in output.glob("*.json")) if output.exists() else 0
        sample = {
            "free": {dev: physical_free(path) for dev, path in self.filesystems.items()},
            "memAvailable": memory, "swapUsed": swap,
            "cpuCount": len(os.sched_getaffinity(0)),
            "logBytes": size("output/producer.log"), "metadataBytes": metadata,
            "ociBytes": size("output/candidate.oci.tar"),
            "stageArchiveBytes": size("toolchain-stage.tar"),
        }
        sample["helperGroup"] = group_sample(self.helper_group)
        if self.group is not None:
            require(directory_identity(self.group) == self.group_binding,
                    "Builder cgroup directory identity changed")
            pid, started, container_id = self.builder_process
            require(process_identity(pid) == started, "Builder PID identity changed")
            leaf = process_group(pid)
            require(container_group(leaf, container_id) == self.group,
                    "Builder left its inspected container scope")
            sample["buildPidCgroup"] = str(leaf)
            sample["buildGroup"] = group_sample(self.group)
        return sample

    def check(self, force=False):
        require(not self.cancelled, "Producer cancellation requested")
        now = time.monotonic()
        elapsed = now - self.started
        require(elapsed <= self.limits["timeoutSeconds"], "Producer deadline exceeded")
        # Download/output chunks still check cancellation/deadline immediately.
        # Full filesystem/cgroup observations have one global one-second cadence.
        if not force and self.last_sample_at is not None and now - self.last_sample_at < 1:
            return
        sample = self.sample()
        resource_check(sample, self.initial, self.limits, elapsed)
        sample["elapsedSeconds"] = elapsed
        self.samples.append(sample)
        self.last_sample_at = now
        require(len(self.samples) <= self.limits["timeoutSeconds"] * 2,
                "Resource evidence exceeded bound")

    def run(self, arguments, cwd=None, timeout=120, capture_output=True, guarded=True,
            progress_guard=None):
        deadline = time.monotonic() + timeout
        if guarded:
            deadline = min(deadline, self.started + self.limits["timeoutSeconds"])
            self.check()
        process = subprocess.Popen(arguments, cwd=cwd, env=self.environment,
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   start_new_session=True)
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ)
        result = bytearray()
        last_check = 0
        try:
            with (self.output / "producer.log").open("ab") as log:
                while selector.get_map() or process.poll() is None:
                    now = time.monotonic()
                    require(now < deadline, "Command deadline exceeded")
                    if guarded and now - last_check >= 1:
                        self.check()
                        last_check = now
                    for key, _ in selector.select(0.2):
                        data = os.read(key.fileobj.fileno(), 65536)
                        if not data:
                            selector.unregister(key.fileobj)
                            continue
                        if guarded:
                            require(log.tell() + len(data) <= self.limits["logBytes"],
                                    "Producer log exceeded bound")
                            log.write(data)
                            log.flush()
                        if progress_guard is not None:
                            progress_guard.feed(data)
                        if capture_output:
                            require(len(result) + len(data) <= 1024 * 1024,
                                    "Command output exceeded bound")
                            result.extend(data)
                require(process.wait(timeout=1) == 0, "Command failed: " + arguments[0])
            return result.decode()
        except BaseException:
            if progress_guard is not None:
                # Cancel the server-side RUN before waiting for the client process group.
                self.stop_builder()
            raise
        finally:
            selector.close()
            # A child may outlive its parent and keep stdout open; close the whole owned group.
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                pass
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=3)
            process.stdout.close()

    def inspect(self, kind, name, guarded=True, timeout=15):
        data = json.loads(self.run(["docker", kind, "inspect", name], guarded=guarded, timeout=timeout))
        require(isinstance(data, list) and len(data) == 1, "Ambiguous Docker resource")
        return data[0]

    def create_builder(self, buildx):
        labels = ["--label", "io.nostr-vpn.seed-job=" + self.owner,
                  "--label", "io.nostr-vpn.seed-source=" + self.pins["product"]["commit"]]
        require(not capture(["docker", "ps", "-aq", "--filter", "name=^/" + self.name + "$"]).strip(),
                "Builder container already exists")
        require(not capture(["docker", "volume", "ls", "-q", "--filter",
                             "name=^" + self.name + "$"]).strip(), "Builder volume already exists")
        self.volume_created = True
        self.save_state()
        self.run(["docker", "volume", "create", *labels, self.name])
        cpus = sorted(os.sched_getaffinity(0))[:self.limits["cpu"]]
        self.container = self.name
        self.save_state()
        self.run(["docker", "run", "-d", "--name", self.name, *labels, "--privileged",
                  "--cgroupns=private", "--cpus=2", "--cpuset-cpus=" + ",".join(map(str, cpus)),
                  "--memory=6g", "--memory-swap=6g", "--pids-limit=512",
                  "--mount", "type=volume,source=" + self.name + ",target=/var/lib/buildkit",
                  self.pins["buildkit"]["image"]], timeout=180)
        self.container = self.name
        info = self.inspect("container", self.name)
        owned_resource(info, self.name, self.owner, self.pins["product"]["commit"])
        require(info["Config"]["Image"] == self.pins["buildkit"]["image"] and
                info["Image"] == self.pins["buildkit"]["configDigest"] and
                info["HostConfig"]["CgroupnsMode"] == "private", "Wrong BuildKit realization")
        host = info["HostConfig"]
        require(host["Memory"] == self.limits["buildMemoryGiB"] * GIB and
                host["MemorySwap"] == host["Memory"] and host["NanoCpus"] == 2 * 10**9 and
                host["PidsLimit"] == self.limits["pids"] and
                host["CpusetCpus"] == ",".join(map(str, cpus)) and
                info["State"]["Running"] is True, "Wrong configured BuildKit resource bounds")
        pid, container_id = info["State"]["Pid"], info["Id"]
        started = process_identity(pid)
        leaf = process_group(pid)
        self.group = container_group(leaf, container_id)
        self.group_binding = directory_identity(self.group)
        require(process_identity(pid) == started, "Builder PID changed during cgroup binding")
        self.builder_process = (pid, started, container_id)
        self.cgroup_proof = {
            "containerId": container_id, "pid": pid, "pidStartTime": started,
            "observedPidCgroup": str(leaf), "aggregateScope": str(self.group),
            "scopeDevice": self.group_binding[0], "scopeInode": self.group_binding[1],
        }
        self.save_state()
        self.check(force=True)
        self.cgroup_proof["initialCounters"] = self.samples[-1]["buildGroup"]
        self.save_state()
        version = self.run(["docker", "exec", self.name, "buildkitd", "--version"]).strip()
        require(self.pins["buildkit"]["version"] in version and
                self.pins["buildkit"]["commit"] in version, "BuildKit version mismatch")
        self.run([str(buildx), "create", "--name", self.name, "--driver", "remote",
                  "docker-container://" + self.name])
        self.builder_created = True
        self.save_state()
        self.run([str(buildx), "inspect", "--builder", self.name, "--bootstrap"])
        return {"version": version, "image": info["Image"], "limits": info["HostConfig"],
                "cgroup": self.cgroup_proof}

    def stop_builder(self):
        """Terminate and verify the owned BuildKit scope before toolchain inspection."""
        require(self.container == self.name, "Missing owned builder to stop")
        old_group = self.group
        info = self.inspect("container", self.name, guarded=False, timeout=5)
        owned_resource(info, self.name, self.owner, self.pins["product"]["commit"])
        self.run(["docker", "rm", "-f", self.name], guarded=False, timeout=10)
        require(not self.run(["docker", "ps", "-aq", "--filter", "name=^/" + self.name + "$"],
                             guarded=False, timeout=5).strip(), "Builder container remains")
        if old_group is not None and old_group.exists():
            require(directory_identity(old_group) == self.group_binding,
                    "Builder cgroup identity changed before closure")
            events = dict(line.split() for line in
                          (old_group / "cgroup.events").read_text().splitlines())
            require(events.get("populated") == "0" and
                    (old_group / "pids.current").read_text().strip() == "0",
                    "Builder cgroup still has processes")
        self.container, self.group = None, None
        self.group_binding, self.builder_process = None, None
        self.save_state()
        return {"closed": True, "containerAbsent": True, "cgroupHasProcesses": False}

    def cleanup(self, buildx):
        signal.setitimer(signal.ITIMER_REAL, 0)
        errors = []
        deadline = time.monotonic() + self.limits["cleanupSeconds"]
        def remaining():
            require(time.monotonic() < deadline, "Cleanup deadline exceeded")
            return min(15, max(1, int(deadline-time.monotonic())))
        def run(args):
            return self.run(args, guarded=False, timeout=remaining())
        def inspect(kind, name):
            return self.inspect(kind, name, guarded=False, timeout=remaining())
        if self.builder_created:
            try:
                run([str(buildx), "rm", self.name])
            except Exception as error:
                errors.append(str(error))
        self.group = None
        for name in (self.inspection_container, self.container):
            if name:
                try:
                    if not run(["docker", "ps", "-aq", "--filter", "name=^/" + name + "$"]).strip():
                        continue
                    info = inspect("container", name)
                    owned_resource(info, name, self.owner, self.pins["product"]["commit"])
                    run(["docker", "rm", "-f", name])
                    require(not run(["docker", "ps", "-aq", "--filter", "name=^/" + name + "$"]).strip(),
                            "Owned container remains")
                except Exception as error:
                    errors.append(str(error))
        if self.inspection_image:
            try:
                present = run(["docker", "image", "ls", "-q", "--no-trunc",
                               self.inspection_image]).strip()
                if present:
                    require(self.inspection_image_id is not None and
                            present == self.inspection_image_id, "Inspection image identity changed")
                    run(["docker", "image", "rm", self.inspection_image])
            except Exception as error:
                errors.append(str(error))
        if self.volume_created:
            try:
                if not run(["docker", "volume", "ls", "-q", "--filter", "name=^" + self.name + "$"]).strip():
                    self.volume_created = False
                else:
                    info = inspect("volume", self.name)
                    owned_resource(info, self.name, self.owner, self.pins["product"]["commit"])
                    require(not run(["docker", "ps", "-aq", "--filter", "volume=" + self.name]).strip(),
                            "Builder volume still in use")
                    run(["docker", "volume", "rm", self.name])
            except Exception as error:
                errors.append(str(error))
        for name in ("toolchain-stage.tar",):
            path = self.work / name
            if path.exists() and path.is_file() and not path.is_symlink():
                path.unlink()
        self.save_state(closed=not errors)
        return {"closed": not errors, "errors": errors, "elapsedSeconds":
                self.limits["cleanupSeconds"] - max(0, deadline-time.monotonic())}
