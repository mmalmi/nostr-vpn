import test from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'

test('Windows underlay binds each artifact to the current candidate', () => {
  const root = mkdtempSync(join(tmpdir(), 'nvpn-underlay-source-'))
  try {
    const git = (...args) => {
      const result = spawnSync('git', args, { cwd: root, encoding: 'utf8' })
      assert.equal(result.status, 0, result.stderr)
      return result.stdout.trim()
    }
    const commit = (path, value) => {
      mkdirSync(dirname(join(root, path)), { recursive: true })
      writeFileSync(join(root, path), value)
      git('add', '.')
      git('commit', '-qm', path)
      return [git('rev-parse', 'HEAD'), git('rev-parse', 'HEAD^{tree}')]
    }
    git('init', '-q')
    git('config', 'user.name', 'Release test')
    git('config', 'user.email', 'release-test@example.invalid')
    commit('scripts/release-component-source.mjs', readFileSync(new URL('./release-component-source.mjs', import.meta.url)))
    const windows = commit('windows/App.cs', 'original Windows product')
    const peer = commit('linux/Cargo.lock', 'updated Linux dependencies')
    const script = readFileSync(new URL('./windows-vm-desktop-underlay-change-e2e.sh', import.meta.url), 'utf8')
    const block = script.split('>"$ARTIFACT_DIR/host-peer-component-proof.json" <<\'JS\'\n')[1].split('\nJS')[0]
    const run = candidate => spawnSync(process.execPath, [
      '--input-type=module', '-', root, root, ...windows, ...candidate,
    ], { input: block, encoding: 'utf8' })
    const result = run(peer)
    assert.equal(result.status, 0, result.stderr)
    const proof = JSON.parse(result.stdout)
    assert.equal(proof.linux.receipt_app_git_sha, peer[0])
    assert.equal(proof.windows.receipt_app_git_sha, windows[0])
    for (const platform of ['linux', 'windows']) {
      assert.equal(proof[platform].candidate_app_git_sha, peer[0])
    }
    const changed = commit('windows/App.cs', 'changed Windows product')
    const rejected = run(changed)
    assert.notEqual(rejected.status, 0)
    assert.match(rejected.stderr, /changed product\/build input windows\/App.cs/)
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})
