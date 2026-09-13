#!/usr/bin/env python3
"""Ask Docker to verify that its filtered context contains vendored manifests."""

import json
import pathlib
import subprocess
import sys


root = pathlib.Path(sys.argv[1]).resolve()
manifests = sorted(root.glob("vendor/*/Cargo.toml"))
if not manifests:
    raise SystemExit("No vendored Cargo manifests found")
dockerfile = "FROM scratch\n"
for manifest in manifests:
    relative = manifest.relative_to(root).as_posix()
    dockerfile += "COPY " + json.dumps([relative, "/" + relative]) + "\n"
subprocess.run(
    ["docker", "buildx", "build", "--output", "type=cacheonly", "--file", "-", str(root)],
    input=dockerfile,
    text=True,
    check=True,
)
print("Docker vendored source context verified")
