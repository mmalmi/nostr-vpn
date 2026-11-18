#!/usr/bin/env bash
# Build candidates only. Physical gates and publication remain separate.
set -euo pipefail
[[ $# == 2 && "$(uname -s)/$(uname -m)" == Linux/x86_64 ]]
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FIPS_ROOT="$(cd "$1" && pwd)"
OUTPUT="$2"
[[ ! -e "$OUTPUT" ]]
mkdir -m 0700 "$OUTPUT"
cd "$ROOT"
app_sha="$(git rev-parse HEAD)"
app_tree="$(git rev-parse 'HEAD^{tree}')"
fips_sha="$(git -C "$FIPS_ROOT" rev-parse HEAD)"
fips_tree="$(git -C "$FIPS_ROOT" rev-parse 'HEAD^{tree}')"
[[ "$fips_sha" == 12a7b154fa2fe8e86483c51ac10708501e50cdfe ]]
[[ -z "$(git diff --name-only HEAD)" && -z "$(git -C "$FIPS_ROOT" status --porcelain)" ]]
mapfile -t packages < <(python3 scripts/verify-cargo-path-patch-lock.py --manifest-specs "$FIPS_ROOT")
python3 scripts/verify-cargo-path-patch-lock.py --validate-specs "${packages[@]}"
root_lock="$(python3 scripts/verify-cargo-path-patch-lock.py --expected-sha256 Cargo.lock "${packages[@]}")"
linux_lock="$(python3 scripts/verify-cargo-path-patch-lock.py --expected-sha256 linux/Cargo.lock "${packages[@]}")"
runs="$HOME/.cache/nostr-vpn-linux-release-builder/runs"
mkdir -p "$runs"
chmod 0700 "$runs"
scratch="$(mktemp -d "$runs/nvpn-linux-native-builder.XXXXXX")"
git bundle create "$scratch/app.bundle" HEAD
git -C "$FIPS_ROOT" bundle create "$scratch/fips.bundle" HEAD
sha() { sha256sum "$1" | awk '{print $1}'; }
cache_id="$(printf '%s\n' "$app_sha:$fips_sha" | sha256sum | awk '{print $1}')"
memory="$(python3 - <<'PY'
from pathlib import Path
total=int(next(line.split()[1] for line in Path('/proc/meminfo').read_text().splitlines() if line.startswith('MemTotal:')))*1024
print(min(10*1024**3,total-2*1024**3))
PY
)"
scripts/host-linux-native-builder-remote.sh \
  "$scratch" "$(sha "$scratch/app.bundle")" "$app_sha" "$app_tree" \
  "$(sha "$scratch/fips.bundle")" "$fips_sha" "$fips_tree" 1.95.0 \
  "$cache_id" hosted-native-v1 "nvpn-linux-target-${cache_id:0:24}" \
  "nvpn-linux-bundle-${cache_id:0:24}" "$root_lock" "$linux_lock" \
  "$(git log -1 --format=%ct)" "$(sha Dockerfile.linux-vm-gate)" \
  "$(sha scripts/build-host-linux-vm-bundle-in-container.sh)" 2 "$memory" 2 - \
  >"$OUTPUT/output.tar"
python3 - "$OUTPUT" "$app_sha" "$app_tree" "$fips_sha" "$fips_tree" <<'PY'
import hashlib,json,os,pathlib,sys
out=pathlib.Path(sys.argv[1]);digest=hashlib.sha256()
with (out/'output.tar').open('rb') as stream:
    for chunk in iter(lambda:stream.read(1024*1024),b''):digest.update(chunk)
receipt={'schema':1,'candidateBuildOnly':True,'releaseGatesPassed':False,'appGitSha':sys.argv[2],'appGitTree':sys.argv[3],
 'fipsGitSha':sys.argv[4],'fipsGitTree':sys.argv[5],'outputTarSha256':digest.hexdigest(),
 'repository':os.environ['GITHUB_REPOSITORY'],'runId':os.environ['GITHUB_RUN_ID'],'runAttempt':os.environ['GITHUB_RUN_ATTEMPT'],
 'workflowRef':os.environ['GITHUB_WORKFLOW_REF']}
(out/'hosted-build.json').write_text(json.dumps(receipt,indent=2)+'\n')
PY
