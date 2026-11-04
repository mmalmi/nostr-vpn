#!/usr/bin/env python3
"""Inventory the established Android host before admitting unsigned compilation.

No signing credentials, device operations or release acceptance belong here.
The first phase only reads installed tools and their identities.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
import urllib.request
import zipfile

PINS = Path(__file__).with_name("android-release-inputs.json")
SIGNING_VARIABLES = (
    "ANDROID_KEYSTORE_PATH", "ANDROID_KEYSTORE_PASSWORD", "ANDROID_KEY_ALIAS",
    "ANDROID_KEY_PASSWORD", "ANDROID_KEYSTORE_B64",
)


def require(value, message):
    if not value:
        raise ValueError(message)


def unsigned_environment(environment):
    require(not any(environment.get(key) for key in SIGNING_VARIABLES),
            "Hosted Android compilation must not receive signing credentials")


def required_free_bytes(capacity):
    require(capacity["physicalFloorBytes"] >= 20 * 1024**3,
            "The physical reserve must remain at least 20 GiB")
    values = [capacity[key] for key in (
        "physicalFloorBytes", "maximumOwnGrowthBudgetBytes", "concurrentGrowthBudgetBytes")]
    require(all(isinstance(value, int) and value >= 0 for value in values), "Invalid capacity budget")
    return sum(values)


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def capture(*arguments):
    completed = subprocess.run(arguments, capture_output=True, text=True, timeout=30)
    require(completed.returncode == 0, "Installed native tool inventory failed")
    return (completed.stdout + completed.stderr).strip()


def properties(path):
    if not path.is_file():
        return {}
    return {key.strip(): value.strip().strip('"')
            for line in path.read_text(errors="replace").splitlines()
            if line.strip() and not line.lstrip().startswith("#") and "=" in line
            for key, value in [line.split("=", 1)]}


def memory():
    result = {}
    for line in Path("/proc/meminfo").read_text().splitlines():
        if line.startswith(("MemTotal:", "MemAvailable:")):
            name, amount, unit = line.split()
            require(unit == "kB", "Unexpected memory unit")
            result[name.rstrip(":") + "Bytes"] = int(amount) * 1024
    return result


def sdk_inventory(sdk, pins):
    result = {"packages": {}, "ndk": None}
    for category in ("platforms", "build-tools", "ndk", "cmdline-tools"):
        root = sdk / category
        result["packages"][category] = {
            child.name: properties(child / "source.properties")
            for child in sorted(root.iterdir()) if child.is_dir()
        } if root.is_dir() else {}
    ndk = sdk / "ndk" / pins["ndkVersion"]
    clang = ndk / "toolchains/llvm/prebuilt/linux-x86_64/bin/clang"
    if clang.is_file():
        result["ndk"] = {
            "properties": properties(ndk / "source.properties"),
            "clangSha256": digest(clang),
            "clangVersion": capture(str(clang), "--version").splitlines()[:2],
        }
    result["buildToolHashes"] = {}
    for version in result["packages"]["build-tools"]:
        directory = sdk / "build-tools" / version
        result["buildToolHashes"][version] = {
            name: digest(directory / name)
            for name in ("aapt2", "zipalign", "apksigner", "lib/apksigner.jar")
            if (directory / name).is_file()
        }
    return result


def java_inventory():
    candidates = []
    for variable in ("JAVA_HOME_17_X64", "JAVA_HOME"):
        value = os.environ.get(variable)
        if value and Path(value).resolve() not in candidates:
            candidates.append(Path(value).resolve())
    results = []
    for root in candidates:
        release = properties(root / "release")
        if not release.get("JAVA_VERSION", "").startswith("17."):
            continue
        results.append({
            "release": {name: release.get(name) for name in
                        ("JAVA_VERSION", "JAVA_RUNTIME_VERSION", "IMPLEMENTOR", "OS_ARCH", "MODULES")},
            "version": [line for line in capture(str(root / "bin/java"), "-version").splitlines()
                        if not line.startswith("Picked up ")],
            "files": {name: digest(root / name) for name in
                      ("bin/java", "bin/javac", "bin/jarsigner", "lib/modules") if (root / name).is_file()},
        })
    return results


def inventory(output, pins):
    require(platform.system() == "Linux" and platform.machine() == "x86_64",
            "Expected the established hosted Linux x86_64 Android route")
    require(os.environ.get("GITHUB_ACTIONS") == "true", "This inventory runs on the hosted producer")
    require(not output.exists(), "Inventory output must be new")
    output.mkdir()
    available = shutil.disk_usage(output).free
    sdk = Path(os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT") or "/nonexistent")
    require(sdk.is_dir(), "The hosted Android SDK is unavailable")
    value = {
        "schema": 1,
        "scope": "Read-only native tool and capacity inventory; no compilation or signing",
        "producerCommit": os.environ.get("GITHUB_SHA"),
        "runId": os.environ.get("GITHUB_RUN_ID"),
        "imageVersion": os.environ.get("ImageVersion"),
        "imageOS": os.environ.get("ImageOS"),
        "os": {key: val for key, val in properties(Path("/etc/os-release")).items()
               if key in ("ID", "VERSION_ID", "PRETTY_NAME")},
        "cpuCount": os.cpu_count(), "memory": memory(),
        "freeBytes": available, "requiredBuildEntryBytes": required_free_bytes(pins["capacity"]),
        "capacity": pins["capacity"], "sdk": sdk_inventory(sdk, pins), "java": java_inventory(),
        "compiled": False, "signed": False, "buildAdmitted": False,
    }
    (output / "inventory.json").write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    print(json.dumps({key: value[key] for key in
                      ("imageVersion", "freeBytes", "requiredBuildEntryBytes", "cpuCount", "memory", "compiled")}))


def qualify_ndk(output, pins):
    require(os.environ.get("GITHUB_ACTIONS") == "true" and platform.system() == "Linux",
            "NDK input qualification runs on the hosted producer")
    require(not output.exists(), "Qualification output must be new")
    output.mkdir()
    initial_free = shutil.disk_usage(output).free
    require(initial_free >= required_free_bytes(pins["capacity"]),
            "20 GiB reserve plus the declared growth budget is unavailable")
    archive_pin = pins["ndkArchive"]
    minimum_free = initial_free
    with tempfile.TemporaryDirectory(prefix="ndk-input-", dir=os.environ["RUNNER_TEMP"]) as temporary:
        archive = Path(temporary) / "ndk.zip"
        sha1, sha256, total = hashlib.sha1(), hashlib.sha256(), 0
        with urllib.request.urlopen(archive_pin["url"], timeout=60) as response, archive.open("xb") as target:
            require(response.geturl().startswith("https://"), "NDK download left HTTPS")
            while block := response.read(1024 * 1024):
                total += len(block)
                require(total <= archive_pin["size"], "NDK archive exceeded the published size")
                minimum_free = min(minimum_free, shutil.disk_usage(output).free)
                require(minimum_free >= pins["capacity"]["physicalFloorBytes"] + 1024**3,
                        "NDK download reached the reserve abort margin")
                target.write(block)
                sha1.update(block)
                sha256.update(block)
        require(total == archive_pin["size"] and sha1.hexdigest() == archive_pin["publishedSha1"],
                "NDK archive differs from Android's published r28c identity")
        with zipfile.ZipFile(archive) as package:
            properties_bytes = package.read("android-ndk-r28c/source.properties")
            require(b"Pkg.Revision = 28.2.13676358" in properties_bytes, "NDK package revision differs")
            expanded_bytes = sum(entry.file_size for entry in package.infolist())
            clang_name = "android-ndk-r28c/toolchains/llvm/prebuilt/linux-x86_64/bin/clang-19"
            with package.open(clang_name) as stream:
                clang_hash = hashlib.file_digest(stream, "sha256").hexdigest()
        sdk = Path(os.environ.get("ANDROID_HOME") or os.environ["ANDROID_SDK_ROOT"])
        sdk_files = {}
        for name in ("android.jar", "core-for-system-modules.jar", "framework.aidl"):
            path = sdk / "platforms/android-36" / name
            if path.is_file():
                sdk_files[name] = digest(path)
        record = {"schema": 1, "source": archive_pin, "size": total,
                  "sha1": sha1.hexdigest(), "sha256": sha256.hexdigest(),
                  "expandedBytes": expanded_bytes, "clangSha256": clang_hash,
                  "sourcePropertiesSha256": hashlib.sha256(properties_bytes).hexdigest(),
                  "sdk36Files": sdk_files,
                  "initialFreeBytes": initial_free, "minimumFreeBytes": minimum_free,
                  "extracted": False, "executed": False, "compiled": False,
                  "producerCommit": os.environ["GITHUB_SHA"], "runId": os.environ["GITHUB_RUN_ID"]}
        (output / "ndk-qualification.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
        print(json.dumps({key: record[key] for key in
                          ("sha256", "expandedBytes", "minimumFreeBytes", "executed", "compiled")}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("inventory", "qualify-ndk"))
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    pins = json.loads(PINS.read_text())
    unsigned_environment(os.environ)
    if args.operation == "inventory":
        inventory(args.output, pins)
    else:
        qualify_ndk(args.output, pins)


if __name__ == "__main__":
    main()
