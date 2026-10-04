import test from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'

const helper = resolve('scripts/lib-release-gate-parallel.sh')
function run(body, serial = '1') {
  const dir = mkdtempSync(join(tmpdir(), 'nvpn-serial-gate-'))
  try {
    const result = spawnSync('/bin/bash', ['-c', `
set -euo pipefail
source "$1"
root="$2"
trap 'release_gate_parallel_cancel_all' EXIT
release_gate_parallel_init "$root/logs"
${body}
`, '_', helper, dir], {
      encoding: 'utf8', timeout: 15_000,
      env: { ...process.env, NVPN_RELEASE_GATE_SERIAL: serial, RELEASE_GATE_PARALLEL_TERM_GRACE_SECONDS: '1' },
    })
    return { ...result, trace: (() => { try { return readFileSync(join(dir, 'trace'), 'utf8') } catch { return '' } })() }
  } finally { rmSync(dir, { recursive: true, force: true }) }
}

test('serial lanes complete before the next lane and preserve later group joins', () => {
  const result = run(`
lane() { echo "$1:start" >>"$root/trace"; sleep 0.1; echo "$1:end" >>"$root/trace"; }
lanes=()
for label in preparation validation network; do
  release_gate_parallel_start "$label" lane "$label"
  lanes+=("$RELEASE_GATE_PARALLEL_LAST_INDEX")
  [[ "$(tail -1 "$root/trace")" == "$label:end" ]]
done
release_gate_parallel_wait_group "\${lanes[@]}"
`)
  assert.equal(result.status, 0, result.stdout + result.stderr)
  assert.equal(result.trace, 'preparation:start\npreparation:end\nvalidation:start\nvalidation:end\nnetwork:start\nnetwork:end\n')
  assert.equal((result.stdout.match(/Release-gate lane passed:/g) ?? []).length, 3)
})

test('serial failures retain their status and stop before the next phase', () => {
  const result = run(`
fail_lane() { echo failed >>"$root/trace"; return 7; }
release_gate_parallel_start broken fail_lane
printf 'must-not-run\\n' >>"$root/trace"
`)
  assert.equal(result.status, 7, result.stdout + result.stderr)
  assert.equal(result.trace, 'failed\n')
  assert.match(result.stderr, /Release-gate lane failed: broken/)
})

test('serial successful parent with an orphaned child fails and cleans the group', () => {
  const result = run(`
orphan() { (trap '' TERM; while :; do sleep 0.1; done) & echo "$!" >"$root/child"; }
set +e
release_gate_parallel_start orphan orphan
status=$?
set -e
[[ "$status" == 1 ]]
! kill -0 "$(cat "$root/child")" 2>/dev/null
echo cleaned >>"$root/trace"
`)
  assert.equal(result.status, 0, result.stdout + result.stderr)
  assert.equal(result.trace, 'cleaned\n')
})

test('invalid serial configuration fails before any lane starts', () => {
  const result = run('echo must-not-run >>"$root/trace"', 'maybe')
  assert.equal(result.status, 2, result.stdout + result.stderr)
  assert.equal(result.trace, '')
})
