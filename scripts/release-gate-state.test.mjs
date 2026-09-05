import test from 'node:test'
import assert from 'node:assert/strict'
import { execFileSync, spawnSync } from 'node:child_process'
import { mkdtempSync, writeFileSync, readFileSync, readdirSync, mkdirSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { initialize, finish, checkpoint, status, retry } from './release-gate-state.mjs'

const versionTools = mkdtempSync(join(tmpdir(), 'nvpn-tool-versions-'))
const originalPath = process.env.PATH
for (const tool of ['rustc', 'cargo', 'java', 'gradle']) {
  writeFileSync(join(versionTools, tool), '#!/bin/sh\nprintf fixture-version\n', { mode: 0o755 })
}
process.env.PATH = `${versionTools}:${originalPath}`
test.after(() => { process.env.PATH = originalPath; rmSync(versionTools, { recursive: true, force: true }) })

const library = resolve('scripts/lib-release-gate-state.sh')
const timing = resolve('scripts/lib-release-gate-timing.sh')
const parallel = resolve('scripts/lib-release-gate-parallel.sh')
function fixture(t) {
  const root = mkdtempSync(join(tmpdir(), 'nvpn-gate-state-'))
  const git = (...args) => execFileSync('git', ['-C', root, ...args], { stdio: 'pipe' })
  git('init', '-q')
  git('config', 'user.name', 'Release fixture')
  git('config', 'user.email', 'fixture@example.invalid')
  writeFileSync(join(root, 'input'), 'original\n')
  writeFileSync(join(root, '.gitignore'), 'artifacts/\nlogs/\ncount\nincorrect-success\n')
  git('add', 'input', '.gitignore')
  git('commit', '-qm', 'fixture')
  t.after(() => rmSync(root, { recursive: true, force: true }))
  return { root, git }
}

// Exercise the real Bash timing/parallel runners and checkpoint boundary,
// with a deliberately failing late command and a durable execution counter.
function attempt(root, late = 'false') {
  return spawnSync('/bin/bash', ['-c', `
    set -euo pipefail
    source "$1"
    source "$2"
    source "$3"
    release_gate_state_init "$4"
    trap 's=$?; release_gate_timing_finish_active "$s"; release_gate_parallel_cancel_all; node "$RELEASE_GATE_STATE_TOOL" finish "$RELEASE_GATE_STATE_DIR" "$s"; exit "$s"' EXIT
    release_gate_timing_init "$4/logs"
    release_gate_parallel_init "$4/logs"
    check() { printf 'executed\\n' >>"$4/count"; }
    release_gate_parallel_start early release_gate_checkpoint_run 'Source quality' check a b c "$4"
    release_gate_parallel_wait_group "$RELEASE_GATE_PARALLEL_LAST_INDEX"
    release_gate_timing_run late ${late}
  `, '_', library, timing, parallel, root], { encoding: 'utf8' })
}

test('a late failure resumes without executing the validated earlier check again', t => {
  const { root } = fixture(t)
  const first = attempt(root)
  assert.equal(first.status, 1, first.stderr)
  const second = attempt(root, 'true')
  assert.equal(second.status, 0, second.stderr)
  assert.equal(readFileSync(join(root, 'count'), 'utf8'), 'executed\n')
  const ledger = status(root)
  assert.equal(ledger.status, 'passed')
  assert.ok(ledger.phases.some(p => p.label === 'Source quality' && p.status === 'reused'))
  assert.ok(ledger.phases.some(p => p.label === 'late' && p.status === 'passed'))
})

test('changed tracked content invalidates reuse even before a new commit', t => {
  const { root } = fixture(t)
  assert.equal(attempt(root).status, 1)
  writeFileSync(join(root, 'input'), 'corrected\n')
  const result = attempt(root, 'true')
  assert.equal(result.status, 0, result.stderr)
  assert.equal(readFileSync(join(root, 'count'), 'utf8'), 'executed\nexecuted\n')
})

test('two unchanged failures block a third attempt before any checks execute', t => {
  const { root } = fixture(t)
  assert.equal(attempt(root).status, 1)
  assert.equal(attempt(root).status, 1)
  const third = attempt(root)
  assert.equal(third.status, 1)
  assert.match(third.stderr, /Two release attempts failed/)
  assert.equal(readFileSync(join(root, 'count'), 'utf8'), 'executed\n')
  retry(root, 'Corrected the external fixture availability')
  const recovered = attempt(root, 'true')
  assert.equal(recovered.status, 0, recovered.stderr)
})

test('a concurrent gate is rejected and cannot remove the first owner', t => {
  const { root } = fixture(t)
  const dir = initialize(root, process.pid)
  assert.throws(() => initialize(root, process.pid), /already owns/)
  assert.throws(() => retry(root, 'Repaired a fixture condition'), /owns/)
  finish(dir, 1)
})

test('device/build phases cannot be cached by the generic checkpoint', t => {
  const { root } = fixture(t)
  const dir = initialize(root, process.pid)
  assert.throws(() => checkpoint(dir, 'Physical mobile WireGuard exit and DNS', 'begin'), /not resumable/)
  finish(dir, 1)
})

test('a candidate commit change during a check rejects its success receipt', t => {
  const { root, git } = fixture(t)
  const dir = initialize(root, process.pid)
  checkpoint(dir, 'Source quality', 'begin')
  writeFileSync(join(root, 'input'), 'new candidate\n')
  git('add', 'input')
  git('commit', '-qm', 'changed')
  assert.throws(() => checkpoint(dir, 'Source quality', 'finish'), /candidate changed/)
  assert.throws(() => finish(dir, 1), /checkout changed/)
})

test('a failed check function cannot continue and manufacture a success checkpoint', t => {
  const { root } = fixture(t)
  const result = spawnSync('/bin/bash', ['-c', `
    set -euo pipefail
    source "$1"
    release_gate_state_init "$2"
    trap 's=$?; node "$RELEASE_GATE_STATE_TOOL" finish "$RELEASE_GATE_STATE_DIR" "$s"' EXIT
    broken() { false; touch "$2/incorrect-success"; }
    release_gate_checkpoint_run 'Source quality' broken a "$2"
  `, '_', library, root], { encoding: 'utf8' })
  assert.equal(result.status, 1, result.stderr)
  const dir = initialize(root, process.pid)
  assert.equal(checkpoint(dir, 'Source quality', 'begin'), 'run')
  finish(dir, 1)
})

test('environment and tool version changes invalidate an otherwise successful check', t => {
  const { root } = fixture(t)
  let dir = initialize(root, process.pid)
  assert.equal(checkpoint(dir, 'Source quality', 'begin'), 'run')
  checkpoint(dir, 'Source quality', 'finish')
  finish(dir, 0)
  const old = process.env.NVPN_GATE_FIXTURE_CONDITION
  process.env.NVPN_GATE_FIXTURE_CONDITION = 'changed'
  try {
    dir = initialize(root, process.pid)
    assert.equal(checkpoint(dir, 'Source quality', 'begin'), 'run')
    checkpoint(dir, 'Source quality', 'finish')
    finish(dir, 0)
    writeFileSync(join(versionTools, 'cargo'), '#!/bin/sh\nprintf changed-version\n', { mode: 0o755 })
    dir = initialize(root, process.pid)
    assert.equal(checkpoint(dir, 'Source quality', 'begin'), 'run')
    finish(dir, 1)
  } finally {
    if (old === undefined) delete process.env.NVPN_GATE_FIXTURE_CONDITION
    else process.env.NVPN_GATE_FIXTURE_CONDITION = old
    writeFileSync(join(versionTools, 'cargo'), '#!/bin/sh\nprintf fixture-version\n', { mode: 0o755 })
  }
})

test('local FIPS changes invalidate checkpoints, and a changed check cannot seal', t => {
  const { root } = fixture(t)
  const fips = fixture(t)
  const old = process.env.NVPN_FIPS_REPO_PATH
  process.env.NVPN_FIPS_REPO_PATH = fips.root
  try {
    let dir = initialize(root, process.pid)
    checkpoint(dir, 'Rust regression checks', 'begin')
    checkpoint(dir, 'Rust regression checks', 'finish')
    finish(dir, 0)
    writeFileSync(join(fips.root, 'input'), 'changed dependency\n')
    dir = initialize(root, process.pid)
    assert.equal(checkpoint(dir, 'Rust regression checks', 'begin'), 'run')
    writeFileSync(join(fips.root, 'input'), 'changed during check\n')
    assert.throws(() => checkpoint(dir, 'Rust regression checks', 'finish'), /inputs changed/)
    assert.throws(() => finish(dir, 1), /checkout changed/)
  } finally {
    if (old === undefined) delete process.env.NVPN_FIPS_REPO_PATH
    else process.env.NVPN_FIPS_REPO_PATH = old
  }
})

test('stale-owner recovery preserves checkpoints and grants one diagnosed retry', t => {
  const { root } = fixture(t)
  const dead = spawnSync('/bin/sh', ['-c', 'exit 0']).pid
  const dir = initialize(root, dead)
  checkpoint(dir, 'Source quality', 'begin')
  checkpoint(dir, 'Source quality', 'finish')
  assert.throws(() => initialize(root, process.pid), /exited without cleanup/)
  retry(root, 'Stopped the abandoned external fixture and verified readiness')
  const next = initialize(root, process.pid)
  assert.equal(checkpoint(next, 'Source quality', 'begin'), 'reuse')
  finish(next, 1)
  assert.throws(() => initialize(root, process.pid), /Two release attempts failed/)
  assert.throws(() => retry(root, 'Stopped the abandoned external fixture and verified readiness'), /already tried/)
})

test('untracked source changes and expired evidence cannot reuse a check', t => {
  const { root } = fixture(t)
  let dir = initialize(root, process.pid)
  checkpoint(dir, 'Source quality', 'begin')
  checkpoint(dir, 'Source quality', 'finish')
  finish(dir, 0)
  writeFileSync(join(root, 'new-source'), 'new code\n')
  dir = initialize(root, process.pid)
  assert.equal(checkpoint(dir, 'Source quality', 'begin'), 'run')
  checkpoint(dir, 'Source quality', 'finish')
  finish(dir, 0)
  for (const name of readdirSync(dir).filter(name => name.startsWith('check-'))) {
    const path = join(dir, name)
    const receipt = JSON.parse(readFileSync(path, 'utf8'))
    receipt.finishedAt = Date.now() - 25 * 60 * 60 * 1000
    writeFileSync(path, JSON.stringify(receipt))
  }
  dir = initialize(root, process.pid)
  assert.equal(checkpoint(dir, 'Source quality', 'begin'), 'run')
  finish(dir, 1)
})


test('an initialization crash before the run record can be recovered', t => {
  const { root } = fixture(t)
  const owner = join(root, 'artifacts', 'release-gate-state', 'owner')
  mkdirSync(owner, { recursive: true })
  const dead = spawnSync('/bin/sh', ['-c', 'exit 0']).pid
  writeFileSync(join(owner, 'pid.json'), JSON.stringify({ pid: dead }))
  retry(root, 'Verified the initializer exited before any phase ran')
  const dir = initialize(root, process.pid)
  finish(dir, 0)
})
