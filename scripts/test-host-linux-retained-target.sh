#!/usr/bin/env bash
# Pure shell/mock integration coverage: never invokes Docker, SSH or a compiler.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT/scripts/lib-host-linux-builder-isolation.sh"
TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/nvpn-retained-target.XXXXXX")"
trap 'rm -rf "$TEST_ROOT"' EXIT
export MOCK_DOCKER_STATE="$TEST_ROOT/state.json"
mkdir "$TEST_ROOT/bin"
cat > "$TEST_ROOT/bin/docker" <<'PY'
#!/usr/bin/env python3
import json, os, pathlib, sys
p=pathlib.Path(os.environ['MOCK_DOCKER_STATE'])
s=json.loads(p.read_text()) if p.exists() else {'volumes':{},'calls':[], 'users': '', 'bytes':4096}
a=sys.argv[1:];s['calls'].append(a)
def done(code=0, out=''):
    p.write_text(json.dumps(s))
    if out: print(out)
    sys.exit(code)
if a[:2]==['volume','inspect']:
    v=s['volumes'].get(a[-1])
    if v is None: done(1)
    if '--format' not in a: done(out=json.dumps(v))
    f=a[a.index('--format')+1]
    if 'release-builder-cache' in f: done(out=v['cache'])
    if 'release-builder-generation' in f: done(out=v['generation'])
    if 'release-builder' in f: done(out=v['role'])
    if '.Options' in f: done(out=json.dumps(v.get('options',None)))
    if '.Driver' in f: done(out='local')
    if '.Mountpoint' in f: done(out='/var/lib/docker/volumes/'+a[-1]+'/_data')
if a[:2]==['volume','create']:
    labels={a[i+1].split('=',1)[0]:a[i+1].split('=',1)[1] for i,x in enumerate(a) if x=='--label'}
    s['volumes'][a[-1]]={'role':labels['to.nostrvpn.release-builder'], 'cache':labels['to.nostrvpn.release-builder-cache'], 'generation':labels['to.nostrvpn.release-builder-generation']}
    done(out=a[-1])
if a[:2]==['volume','rm']:
    del s['volumes'][a[-1]];done()
if a and a[0]=='ps': done(code=s.get('ps_exit',0),out=s['users'])
if a and a[0]=='run':
    if 'rustc -vV;' in a[-1]:
        done(out=s.get('toolchain','rustc 1.95.0 (fixture)\nbinary: rustc\nhost: x86_64-unknown-linux-gnu\ncargo 1.95.0\nx86_64-linux-gnu\n13'))
    if 'du -s -B1' in a[-1]: done(out=str(s['bytes']))
if a[:2]==['container','inspect']: done(1)
done(90, 'UNEXPECTED MOCK DOCKER CALL: '+repr(a))
PY
chmod +x "$TEST_ROOT/bin/docker"
export PATH="$TEST_ROOT/bin:$PATH"
# Refuse any accidental external build or remote execution from this harness.
for command in cargo rustc ssh scp; do
  printf '#!/bin/sh\nexit 99\n' > "$TEST_ROOT/bin/$command"
  chmod +x "$TEST_ROOT/bin/$command"
done
fail() { echo "retained target harness: $*" >&2; exit 1; }
reject() { if "$@" >"$TEST_ROOT/rejection.log" 2>&1; then fail "unexpected acceptance: $*"; fi; }
state() {
  python3 - "$MOCK_DOCKER_STATE" "$@" <<'PY'
import json,pathlib,sys
p=pathlib.Path(sys.argv[1]);s=json.loads(p.read_text())
exec(sys.argv[2])
p.write_text(json.dumps(s))
PY
}
export NVPN_HOST_LINUX_VM_RETAIN_TARGET=1
export NVPN_HOST_LINUX_VM_BUILD_CPUS=2 NVPN_HOST_LINUX_VM_BUILD_MEMORY=10g
export NVPN_HOST_LINUX_VM_CARGO_JOBS=2 NVPN_HOST_LINUX_VM_TARGET_MAX_BYTES=8589934592
CACHE="$(printf cache | shasum -a256 | cut -d' ' -f1)"
IMAGE="sha256:$(printf image | shasum -a256 | cut -d' ' -f1)"
LOCK="$(printf lock | shasum -a256 | cut -d' ' -f1)"
LINUX_LOCK="$(printf linux | shasum -a256 | cut -d' ' -f1)"
PAYLOAD="$(printf payload | shasum -a256 | cut -d' ' -f1)"
prepare() { host_linux_builder_prepare_retained_target "$CACHE" "$IMAGE" 1.95.0 "$LOCK" "$LINUX_LOCK" "$PAYLOAD" fixture-owner; }
NVPN_HOST_LINUX_VM_BUILD_SCOPE=daemon prepare
[[ "$HOST_LINUX_RETAINED_REUSED" == 0 ]] || fail 'new target marked reused'
VOLUME="$HOST_LINUX_RETAINED_VOLUME"; GENERATION="$HOST_LINUX_RETAINED_GENERATION"
NVPN_HOST_LINUX_VM_BUILD_SCOPE=full prepare
[[ "$HOST_LINUX_RETAINED_REUSED" == 1 && "$HOST_LINUX_RETAINED_VOLUME" == "$VOLUME" && "$HOST_LINUX_RETAINED_GENERATION" == "$GENERATION" ]] || fail 'compatible target not reused across scopes'
state "assert len(s['volumes'])==1; assert not any(x[:2]==['volume','rm'] for x in s['calls'])"
host_linux_builder_check_retained_target_size "$VOLUME" "$IMAGE" "$CACHE" fixture-owner
for field in IMAGE LOCK LINUX_LOCK PAYLOAD; do
  (
    printf -v "$field" '%s' "$(printf changed | shasum -a256 | cut -d' ' -f1)"
    [[ "$field" != IMAGE ]] || IMAGE="sha256:$IMAGE"
    reject prepare
  )
done
state "assert len(s['volumes'])==1; assert not any(x[:2]==['volume','rm'] for x in s['calls'])"
state "s['toolchain']='rustc 1.94.0 (wrong)'"
reject prepare
state "s['toolchain']='rustc 1.95.0 (different compiler build)'"
reject prepare
state "s.pop('toolchain')"
state "s['ps_exit']=1"
reject prepare
reject host_linux_builder_remove_target_volume "$VOLUME" "$CACHE" "$GENERATION"
state "s['ps_exit']=0"
state "s['users']='some-other-container'"
reject prepare
reject host_linux_builder_remove_target_volume "$VOLUME" "$CACHE" "$GENERATION"
state "s['users']=''"
state "s['bytes']=8589934593"
reject host_linux_builder_check_retained_target_size "$VOLUME" "$IMAGE" "$CACHE" fixture-owner
state "s['bytes']=8589934592"
host_linux_builder_check_retained_target_size "$VOLUME" "$IMAGE" "$CACHE" fixture-owner
state "s['volumes'][next(iter(s['volumes']))]['options']={'type':'tmpfs'}"
reject prepare
state "s['volumes'][next(iter(s['volumes']))].pop('options')"
for field in NVPN_HOST_LINUX_VM_BUILD_CPUS NVPN_HOST_LINUX_VM_BUILD_MEMORY NVPN_HOST_LINUX_VM_CARGO_JOBS NVPN_HOST_LINUX_VM_TARGET_MAX_BYTES; do
  ( unset "$field"; reject host_linux_builder_resource_args )
done
( export NVPN_HOST_LINUX_VM_TARGET_TMPFS_BYTES=1024; reject host_linux_builder_resource_args )
( export NVPN_HOST_LINUX_VM_TARGET_MAX_BYTES=-1; reject host_linux_builder_resource_args )
( export NVPN_HOST_LINUX_VM_RETAIN_TARGET=bad; reject host_linux_builder_resource_args )
# Exercise the actual remote cleanup trap, including cancellation before lock.
python3 - "$ROOT/scripts/host-linux-native-builder-remote.sh" "$TEST_ROOT/cleanup.sh" <<'PY'
import pathlib,sys
text=pathlib.Path(sys.argv[1]).read_text()
start=text.index('cleanup() {');end=text.index("\n\n[[ \"$(uname -s)",start)
pathlib.Path(sys.argv[2]).write_text(text[start:end]+'\n')
PY
for code in 0 1 143; do
  mkdir -p "$TEST_ROOT/run/app/scripts"
  cp "$ROOT/scripts/lib-host-linux-builder-isolation.sh" "$TEST_ROOT/run/app/scripts/"
  set +e
  (
    REMOTE_ROOT="$TEST_ROOT/run"; CONTAINER_OWNED=1; OWNER_CONTAINER_OWNED=0
    TARGET_VOLUME_OWNED=1; TARGET_VOLUME_RETAINED=1
    TARGET_VOLUME_NAME="$VOLUME"; BUILD_CACHE_ID="$CACHE"; TARGET_CACHE_GENERATION="$GENERATION"; CONTAINER_NAME=fixture
    source "$TEST_ROOT/cleanup.sh"
    trap cleanup EXIT
    exit "$code"
  )
  result=$?
  set -e
  [[ "$result" == "$code" && ! -e "$TEST_ROOT/run" ]] || fail 'cleanup changed status or retained source staging'
  state "assert len(s['volumes'])==1"
done
mkdir -p "$TEST_ROOT/run/app/scripts"
cp "$ROOT/scripts/lib-host-linux-builder-isolation.sh" "$TEST_ROOT/run/app/scripts/"
cat > "$TEST_ROOT/cancel.sh" <<'CANCEL'
set -euo pipefail
REMOTE_ROOT="$1/run"; CONTAINER_OWNED=1; OWNER_CONTAINER_OWNED=0
TARGET_VOLUME_OWNED=1; TARGET_VOLUME_RETAINED=1
TARGET_VOLUME_NAME="$2"; BUILD_CACHE_ID="$3"; TARGET_CACHE_GENERATION="$4"; CONTAINER_NAME=fixture
source "$1/cleanup.sh"
kill -TERM "$$"
exit 99
CANCEL
set +e
bash "$TEST_ROOT/cancel.sh" "$TEST_ROOT" "$VOLUME" "$CACHE" "$GENERATION"
result=$?
set -e
[[ "$result" == 143 && ! -e "$TEST_ROOT/run" ]] || fail 'actual TERM was not preserved as failure'
state "assert len(s['volumes'])==1"
mkdir -p "$TEST_ROOT/run"
(
  REMOTE_ROOT="$TEST_ROOT/run"; CONTAINER_OWNED=0; OWNER_CONTAINER_OWNED=0
  TARGET_VOLUME_OWNED=0; TARGET_VOLUME_RETAINED=0
  source "$TEST_ROOT/cleanup.sh"; trap cleanup EXIT
)
state "assert len(s['volumes'])==1"
# Explicit owner retirement is still possible, but only for matching inactive data.
reject host_linux_builder_remove_target_volume "$VOLUME" "$CACHE" mismatch
host_linux_builder_remove_target_volume "$VOLUME" "$CACHE" "$GENERATION"
state "assert not s['volumes']"
# Default non-retained scratch creation/recreation still discards only its own cache.
export NVPN_HOST_LINUX_VM_RETAIN_TARGET=0
host_linux_builder_create_fresh_target_volume scratch "$CACHE" fresh
host_linux_builder_create_fresh_target_volume scratch "$CACHE" fresh
state "assert list(s['volumes'])==['scratch']"
host_linux_builder_remove_target_volume scratch "$CACHE" fresh
state "assert not s['volumes']; assert all('--cpus' in a and '--memory' in a and '--name' in a and '--label' in a for a in s['calls'] if a[0]=='run')"
printf 'PASS retained target reuse, compatibility, ownership, bounds, success/failure/cancellation cleanup and default scratch behavior (mock Docker only)\n'
