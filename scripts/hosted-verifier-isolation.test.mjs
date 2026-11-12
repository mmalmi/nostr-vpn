import assert from 'node:assert/strict'
import { execFileSync, spawnSync } from 'node:child_process'
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import test from 'node:test'

test('external verifier policies inspect a clean frozen checkout and still reject product edits', () => {
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'nvpn-verifier-isolation-')))
  try {
    const product = join(root, 'product')
    const verifier = join(root, 'verifier')
    for (const dir of [product, join(product, 'linux'), join(verifier, 'scripts'), join(root, 'bin')]) mkdirSync(dir, { recursive: true })
    const git = (...args) => execFileSync('git', ['-C', product, ...args], { encoding: 'utf8' }).trim()
    git('init', '-q')
    writeFileSync(join(product, 'input.rs'), '// frozen product\n')
    git('add', '.')
    git('-c', 'user.name=Release Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-qm', 'frozen fixture')
    for (const name of ['security-audit-rust.sh', 'check-source-file-lines.sh']) {
      copyFileSync(join('scripts', name), join(verifier, 'scripts', name))
    }
    writeFileSync(join(root, 'bin/cargo'), `#!/bin/sh
test "$1" = audit || exit 90
test "$2" = --version && exit 0
case "$PWD" in "$TEST_PRODUCT"|"$TEST_PRODUCT/linux") echo audited-frozen-product ;; *) exit 91 ;; esac
`, { mode: 0o755 })
    const source = readFileSync('scripts/release-gate.sh', 'utf8')
    const roots = source.match(/^VERIFIER_ROOT=.*\nROOT_DIR=.*$/m)?.[0]
    const seal = source.match(/^seal_release_gate_app_candidate\(\) \{[\s\S]*?^\}/m)?.[0]
    assert.ok(roots && seal)
    const runner = join(verifier, 'scripts/run.sh')
    writeFileSync(runner, `set -euo pipefail
${roots}
source "$TEST_COMMON"
${seal}
seal_release_gate_app_candidate
bash "$VERIFIER_ROOT/scripts/security-audit-rust.sh"
bash "$VERIFIER_ROOT/scripts/check-source-file-lines.sh"
`)
    const run = () => spawnSync('bash', [runner], {
      encoding: 'utf8', timeout: 10_000,
      env: { ...process.env, PATH: `${join(root, 'bin')}:${process.env.PATH}`,
        NVPN_RELEASE_APP_REPO_PATH: product, NVPN_EXPECTED_APP_GIT_SHA: git('rev-parse', 'HEAD'),
        NVPN_EXPECTED_APP_GIT_TREE: git('rev-parse', 'HEAD^{tree}'),
        NVPN_LOCAL_FIPS_SESSION_CARGO_LOCK_SHA256: '',
        TEST_COMMON: resolve('scripts/release_common.sh'), TEST_PRODUCT: product },
    })
    const passed = run()
    assert.equal(passed.status, 0, passed.stderr)
    assert.equal(passed.stdout.match(/audited-frozen-product/g)?.length, 2)
    assert.equal(git('status', '--porcelain'), '')
    writeFileSync(join(product, 'input.rs'), '// changed product\n')
    const rejected = run()
    assert.notEqual(rejected.status, 0)
    assert.match(rejected.stderr, /source checkout is dirty/)
    assert.doesNotMatch(rejected.stdout, /audited-frozen-product/)
  } finally { rmSync(root, { recursive: true, force: true }) }
})
