import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'

test('frozen test-file style debt cannot exempt growth, changed content or another candidate', () => {
  const script = readFileSync('scripts/check-source-file-lines.sh', 'utf8')
  const file = 'crates/nostr-vpn-core/src/config/tests.rs'
  const original = readFileSync(file, 'utf8')
  const git = spawnSync('which', ['git'], { encoding: 'utf8' }).stdout.trim()
  for (const [revision, source, status] of [
    ['52a1f8eee3cf19c5bc467a3ccf39d3d6d74437f4', original, 0],
    ['52a1f8eee3cf19c5bc467a3ccf39d3d6d74437f4', `${original}\n`, 1],
    ['52a1f8eee3cf19c5bc467a3ccf39d3d6d74437f4', original.replace('use ', '// use '), 1],
    ['a'.repeat(40), original, 1],
  ]) {
    const root = mkdtempSync(join(tmpdir(), 'nvpn-source-size-'))
    try {
      for (const dir of ['scripts', 'bin', 'crates/nostr-vpn-core/src/config']) mkdirSync(join(root, dir), { recursive: true })
      writeFileSync(join(root, 'scripts/check-source-file-lines.sh'), script)
      writeFileSync(join(root, file), source)
      writeFileSync(join(root, 'bin/git'), `#!/bin/sh
if test "$1" = -C; then cd "$2"; shift 2; fi
case "$1" in
  ls-files) printf '%s\\0' '${file}' ;;
  rev-parse) echo "$TEST_REVISION" ;;
  hash-object) exec "$TEST_REAL_GIT" "$@" ;;
  *) exit 90 ;;
esac
`, { mode: 0o755 })
      const result = spawnSync('bash', [join(root, 'scripts/check-source-file-lines.sh')], {
        encoding: 'utf8', timeout: 10_000,
        env: { ...process.env, PATH: `${join(root, 'bin')}:${process.env.PATH}`,
          TEST_REVISION: revision, TEST_REAL_GIT: git, NVPN_SOURCE_FILE_LINE_LIMIT: '1000' },
      })
      assert.equal(result.status, status, result.stderr)
    } finally { rmSync(root, { recursive: true, force: true }) }
  }
})
