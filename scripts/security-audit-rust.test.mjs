import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'

test('frozen runtime advisory exceptions require its exact commit and unchanged inputs', () => {
  const source = readFileSync('scripts/security-audit-rust.sh', 'utf8')
  for (const [revision, changed, accepted] of [
    ['52a1f8eee3cf19c5bc467a3ccf39d3d6d74437f4', '0', true],
    ['52a1f8eee3cf19c5bc467a3ccf39d3d6d74437f4', '1', false],
    ['a'.repeat(40), '0', false],
  ]) {
    const root = mkdtempSync(join(tmpdir(), 'nvpn-audit-policy-'))
    try {
      for (const dir of ['scripts', 'bin', 'linux']) mkdirSync(join(root, dir))
      writeFileSync(join(root, 'scripts/security-audit-rust.sh'), source)
      writeFileSync(join(root, 'bin/git'), `#!/bin/sh
case "$1" in
  rev-parse) echo "$TEST_REVISION" ;;
  diff) test "$2" = --quiet && test "$TEST_CHANGED" = 0 ;;
  *) exit 90 ;;
esac
`, { mode: 0o755 })
      writeFileSync(join(root, 'bin/cargo'), `#!/bin/sh
test "$1" = audit || exit 90
test "$2" = --version && exit 0
printf '%s\\n' "$*" >> "$TEST_AUDIT_ARGS"
`, { mode: 0o755 })
      const result = spawnSync('bash', [join(root, 'scripts/security-audit-rust.sh')], {
        encoding: 'utf8', timeout: 10_000,
        env: { ...process.env, PATH: `${join(root, 'bin')}:${process.env.PATH}`,
          TEST_REVISION: revision, TEST_CHANGED: changed, TEST_AUDIT_ARGS: join(root, 'args') },
      })
      assert.equal(result.status, 0, result.stderr)
      const calls = readFileSync(join(root, 'args'), 'utf8').trim().split('\n')
      assert.equal(calls.length, 2, 'both lockfiles remain audited')
      for (const call of calls) {
        assert.ok(call.includes('--deny warnings'))
        for (const id of ['0459', '0486', '0441']) {
          assert.equal(call.includes(`--ignore RUSTSEC-2026-${id}`), accepted)
        }
      }
    } finally { rmSync(root, { recursive: true, force: true }) }
  }
})
