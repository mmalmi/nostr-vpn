import test from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { resolve, join } from 'node:path'
import { mkdtempSync, mkdirSync, readFileSync, existsSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'

const helper = resolve('scripts/lib-host-linux-builder-isolation.sh')
function resourceArgs(env = {}) {
  return spawnSync('/bin/bash', ['-c', `
set -euo pipefail
source "$1"
host_linux_builder_resource_args
printf '%s\\n' "\${HOST_LINUX_BUILDER_RESOURCE_ARGS[@]}"
`, '_', helper], { encoding: 'utf8', env: { ...process.env,
    NVPN_HOST_LINUX_VM_BUILD_CPUS: '', NVPN_HOST_LINUX_VM_BUILD_MEMORY: '', NVPN_HOST_LINUX_VM_CARGO_JOBS: '', ...env } })
}

test('default Linux builder resource arguments preserve existing behavior', () => {
  const r = resourceArgs()
  assert.equal(r.status, 0, r.stderr)
  assert.deepEqual(r.stdout.trim().split('\n'), ['--env', 'CARGO_INCREMENTAL=0'])
})

test('Linux builder caps CPU, memory without extra swap, and Cargo jobs', () => {
  const r = resourceArgs({ NVPN_HOST_LINUX_VM_BUILD_CPUS: '2', NVPN_HOST_LINUX_VM_BUILD_MEMORY: '6g', NVPN_HOST_LINUX_VM_CARGO_JOBS: '2' })
  assert.equal(r.status, 0, r.stderr)
  assert.deepEqual(r.stdout.trim().split('\n'), ['--env', 'CARGO_INCREMENTAL=0', '--cpus', '2', '--memory', '6g', '--memory-swap', '6g', '--env', 'CARGO_BUILD_JOBS=2'])
})

test('nonpositive and malformed limits are rejected before returning Docker arguments', () => {
  for (const [key, values] of Object.entries({
    NVPN_HOST_LINUX_VM_BUILD_CPUS: ['0', '-1', 'nan', '2 --privileged'],
    NVPN_HOST_LINUX_VM_BUILD_MEMORY: ['0', '0g', '-1', '6g --privileged'],
    NVPN_HOST_LINUX_VM_CARGO_JOBS: ['0', '-1', 'auto', '2\n3'],
  })) for (const value of values) {
    const r = resourceArgs({ [key]: value })
    assert.equal(r.status, 2, `${key}: ${r.stderr}`)
    assert.equal(r.stdout, '')
  }
})

test('the remote request carries limits and rejects invalid values before SSH', () => {
  const root = mkdtempSync(join(tmpdir(), 'nvpn-builder-limits-'))
  try {
    for (const name of ['app', 'fips']) {
      const cwd = join(root, 'source', name)
      mkdirSync(cwd, { recursive: true })
      for (const args of [ ['init', '-q'], ['-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', '-c', 'commit.gpgsign=false', 'commit', '-q', '--allow-empty', '-m', 'Fixture'] ]) {
        const r = spawnSync('git', args, { cwd, encoding: 'utf8' })
        assert.equal(r.status, 0, r.stderr)
      }
    }
    for (const cpus of ['2', '', '0']) {
      const capture = join(root, `ssh-${cpus}`)
      const r = spawnSync('/bin/bash', ['-c', `
set -euo pipefail
ROOT="$1"
fixture="$2"
capture="$3"
source "$ROOT/scripts/lib-host-linux-builder-isolation.sh"
source "$ROOT/scripts/lib-host-linux-native-builder.sh"
capture_ssh() {
  if [[ "$1" == bash ]]; then printf '%s\\n' "$@" >"$capture"; return 77; fi
  printf '%s\\n' "$fixture/.cache/nostr-vpn-linux-release-builder/runs/nvpn-linux-native-builder.abcdef"
}
host_linux_native_builder_commands() { NVPN_HOST_LINUX_NATIVE_SSH=(capture_ssh); NVPN_HOST_LINUX_NATIVE_SCP=(true); }
host_linux_native_builder_run "$fixture" a b c d 1.95.0 e f g h i j 1 k l
`, '_', process.cwd(), root, capture], { encoding: 'utf8', env: { ...process.env,
        NVPN_HOST_LINUX_VM_NATIVE_BUILDER_HOST: 'fixture', NVPN_HOST_LINUX_VM_BUILD_CPUS: cpus,
        NVPN_HOST_LINUX_VM_BUILD_MEMORY: cpus ? '6g' : '', NVPN_HOST_LINUX_VM_CARGO_JOBS: cpus ? '2' : '' } })
      assert.equal(r.status, cpus !== '0' ? 77 : 2, r.stdout + r.stderr)
      if (cpus !== '0') assert.deepEqual(readFileSync(capture, 'utf8').trim().split('\n').slice(-3), cpus ? ['2', '6g', '2'] : ['-', '-', '-'])
      else assert.equal(existsSync(capture), false)
    }
  } finally { rmSync(root, { recursive: true, force: true }) }
})

test('the production remote argument parser applies limits to its build container', () => {
  const remote = readFileSync('scripts/host-linux-native-builder-remote.sh', 'utf8')
  const parser = remote.slice(0, remote.indexOf('\nEXPECTED_RUNS_ROOT='))
  const phase = remote.match(/^run_builder_phase\(\) \{[\s\S]*?^\}/m)?.[0]
  assert.ok(phase)
  const r = spawnSync('/bin/bash', ['-c', `
${parser}
source "$FIXTURE_HELPER"
host_linux_builder_resource_args
for variable in BUILDER_UID BUILDER_GID CONTAINER_IMAGE_ID; do printf -v "$variable" fixture; done
host_linux_builder_stop_container() { :; }
docker() { python3 -c 'import json,sys; print(json.dumps(sys.argv[1:]))' "$@"; }
${phase}
run_builder_phase build
`, '_', ...Array.from({ length: 17 }, () => 'fixture'), '2', '6g', '2'], {
    encoding: 'utf8', env: { ...process.env, FIXTURE_HELPER: helper },
  })
  assert.equal(r.status, 0, r.stderr)
  const argv = JSON.parse(r.stdout)
  for (const [flag, value] of [['--cpus', '2'], ['--memory', '6g'], ['--memory-swap', '6g']]) {
    assert.equal(argv[argv.indexOf(flag) + 1], value)
  }
  assert.ok(argv.includes('CARGO_BUILD_JOBS=2'))
  assert.ok(argv.includes('CARGO_INCREMENTAL=0'))
})
