#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

# This is the bounded, host-independent subset that protects the expensive
# exact-candidate run itself. The exhaustive release-tooling contracts remain
# an independent CI job; these checks finish before any VM or phone is touched.
for script in \
  scripts/build-linux-arm64-cli-gate.sh \
  scripts/release-gate.sh \
  scripts/lib-release-gate-parallel.sh \
  scripts/lib-release-gate-state.sh \
  scripts/mobile-release-join-e2e.sh
do
  bash -n "$script"
done

node --test scripts/release-gate-state.test.mjs
node --test scripts/windows-manual-join-preparation.test.mjs
node --test scripts/github-release-publication.test.mjs
scripts/test-release-gate-parallel-harness.sh
scripts/test-release-gate-timing-harness.sh
scripts/test-desktop-network-handoff-harness.sh
if [[ "$(uname -s)" == Darwin ]]; then
  # These artifact fixtures require Apple's plist tools, but no devices.
  scripts/test-mobile-release-join-gate-harness.sh
  scripts/test-mobile-ios-release-runner-harness.sh
fi

python3 - scripts/e2e-umbrel-auth-join-docker.sh <<'PY'
import pathlib
import socket
import sys

source = pathlib.Path(sys.argv[1]).read_text()
fixture = source.split('<<\'PY\' &\n', 1)[1].split('\nPY\n', 1)[0]
fixture = fixture.replace('.serve_forever()', '.server_close()')
def reject_dns(*args):
    raise AssertionError("local login fixture must not resolve the host name")
socket.getfqdn = reject_dns
sys.argv = ["login-fixture", "0", "fixture-secret", "fixture-password"]
exec(compile(fixture, "umbrel-login-fixture", "exec"))
print("Umbrel local login fixture starts without reverse DNS")
PY

python3 - scripts/release-gate.sh scripts/build-linux-arm64-cli-gate.sh <<'PY'
import pathlib
import sys

gate, arm64 = [pathlib.Path(path).read_text(encoding="utf-8") for path in sys.argv[1:]]
start = gate.index('"Linux ARM64 CLI"')
wait = gate.index('release_gate_parallel_wait_group "${platform_preparation_lanes[@]}"')
if start > wait:
    raise SystemExit("Linux ARM64 CLI no longer overlaps platform preparation")
for required in (
    "exact native-smoked Linux ARM64 static CLI",
    "aarch64-unknown-linux-musl",
    "--platform linux/arm64",
    "--pull never",
    "--entrypoint sh",
    'SMOKE_IMAGE="${NVPN_LINUX_ARM64_SMOKE_IMAGE:-ubuntu:24.04}"',
    "nativeStatusSmokePassed",
    "nativeSmokeArchiveSha256",
):
    if required not in arm64:
        raise SystemExit(f"Linux ARM64 CLI receipt lane is missing {required}")
PY

printf 'release gate orchestration checks passed\n'
