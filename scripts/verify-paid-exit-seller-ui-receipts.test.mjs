import test from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const verifier = new URL('./verify-paid-exit-seller-ui-receipts.mjs', import.meta.url).pathname
const hash = (bytes) => createHash('sha256').update(bytes).digest('hex')

function fixture(t) {
  const root = mkdtempSync(join(tmpdir(), 'nvpn-seller-proof-'))
  t.after(() => rmSync(root, { recursive: true, force: true }))
  const git = (...args) => {
    const result = spawnSync('git', args, { cwd: root, encoding: 'utf8' })
    assert.equal(result.status, 0, result.stderr)
    return result.stdout.trim()
  }
  git('init', '-q')
  git('config', 'user.name', 'Release test')
  git('config', 'user.email', 'release-test@example.invalid')
  const commit = (path, content) => {
    writeFileSync(join(root, path), content)
    git('add', path)
    git('-c', 'commit.gpgSign=false', 'commit', '-qm', 'test source')
    return { sha: git('rev-parse', 'HEAD'), tree: git('rev-parse', 'HEAD^{tree}') }
  }
  const source = commit('Cargo.toml', '[workspace]\n')
  const receipt = (platform) => ({
    receiptSchema: 1, platform, case: 'paid-exit-seller',
    evidenceSource: 'shipped-ui-restart-readback', releaseBlackbox: true,
    savedViaShippedUi: true, enabledViaShippedUi: true, uiRestartReadback: true,
    privateStateRead: false, paidExitEnabled: true, paidExitPriceMsatPerGb: 1_000_000,
    paidExitCountryCode: 'FI', paidExitAcceptedMints: ['http://cashu-mint:3338'],
    appGitSha: source.sha, appGitTree: source.tree,
  })
  const receipts = { linux: receipt('linux'), macos: receipt('macos') }
  const output = join(root, 'summary.json')
  const run = (candidate = source, platforms = ['linux', 'macos']) => {
    for (const [platform, value] of Object.entries(receipts)) {
      writeFileSync(join(root, `${platform}.json`), JSON.stringify(value))
    }
    return spawnSync(process.execPath, [verifier,
      '--candidate-root', root, '--app-git-sha', candidate.sha,
      '--app-git-tree', candidate.tree, '--output', output,
      ...platforms.map((platform) => `${platform}=${join(root, `${platform}.json`)}`),
    ], { encoding: 'utf8' })
  }
  return { root, git, commit, source, receipts, output, run }
}

test('seller CLI binds both exact-source public UI receipts', (t) => {
  const f = fixture(t)
  const result = f.run()
  assert.equal(result.status, 0, result.stderr)
  const summary = JSON.parse(readFileSync(f.output))
  assert.equal(summary.appGitSha, f.source.sha)
  assert.equal(summary.allSupportedPlatformsSavedEnabledAndRestartRead, true)
  assert.deepEqual(summary.platformSourceEquivalence, {})
  for (const platform of ['linux', 'macos']) {
    assert.equal(summary.platforms[platform], hash(readFileSync(join(f.root, `${platform}.json`))))
  }
})

test('seller CLI reuses unchanged product inputs without relabeling original evidence', (t) => {
  const f = fixture(t)
  mkdirSync(join(f.root, 'scripts'))
  f.commit('scripts/verify-paid-exit-seller-ui-receipts.py', '# previous verifier\n')
  f.commit('scripts/verify-paid-exit-seller-ui-receipts.mjs', '// current verifier\n')
  const candidate = f.commit('scripts/release-gate.sh', '# changed orchestration only\n')
  Object.assign(f.receipts.linux, { appGitSha: candidate.sha, appGitTree: candidate.tree })
  const result = f.run(candidate)
  assert.equal(result.status, 0, result.stderr)
  const summary = JSON.parse(readFileSync(f.output))
  assert.deepEqual(Object.keys(summary.platformSourceEquivalence), ['macos'])
  const proof = summary.platformSourceEquivalence.macos
  assert.equal(proof.policy, 'unchanged-platform-product-inputs-v1')
  assert.equal(proof.receipt_app_git_sha, f.source.sha)
  assert.equal(proof.candidate_app_git_sha, candidate.sha)
  assert.equal(JSON.parse(readFileSync(join(f.root, 'macos.json'))).appGitSha, f.source.sha)
})

for (const failure of ['changed product', 'forged tree', 'non-ancestor', 'private state', 'missing platform', 'unsupported platform']) {
  test(`seller CLI fails closed for ${failure}`, (t) => {
    const f = fixture(t)
    let candidate = f.source
    let platforms = ['linux', 'macos']
    if (failure === 'changed product') candidate = f.commit('Cargo.toml', '[workspace]\n# product changed\n')
    if (failure === 'forged tree') f.receipts.macos.appGitTree = 'f'.repeat(40)
    if (failure === 'non-ancestor') {
      const future = f.commit('README.md', 'later source\n')
      Object.assign(f.receipts.macos, { appGitSha: future.sha, appGitTree: future.tree })
    }
    if (failure === 'private state') f.receipts.macos.privateStateRead = true
    if (failure === 'missing platform') platforms = ['linux']
    if (failure === 'unsupported platform') platforms.push('ios')
    const result = f.run(candidate, platforms)
    assert.notEqual(result.status, 0)
    const messages = {
      'changed product': /changed product\/build input Cargo.toml/,
      'forged tree': /recorded tree is not the commit tree/,
      'non-ancestor': /not an ancestor/,
      'private state': /privateStateRead differs/,
      'missing platform': /Expected receipts for linux and macos/,
      'unsupported platform': /Invalid or duplicate platform=receipt/,
    }
    assert.match(result.stderr, messages[failure])
    assert.equal(existsSync(f.output), false, 'failed validation must not issue a summary')
  })
}
