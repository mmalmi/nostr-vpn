import test from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { generateKeyPairSync } from 'node:crypto'
import { chmodSync, copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import {
  expectedStartosVersion,
  readStartosSourceVersion,
  resolveStartosRevision,
  resolveStartosTarget,
  startosReleaseAssetName,
  validateStartosCliVersion,
  validateStartosManifest,
} from './startos-release.mjs'

test('validateStartosCliVersion requires the builder that preserves virtual networking', () => {
  assert.doesNotThrow(() => validateStartosCliVersion('start-cli 1.1.0'))
  assert.throws(
    () => validateStartosCliVersion('start-cli 0.4.0-beta.9'),
    /expected start-cli 1\.1\.0/,
  )
})

test('release preflight rejects old tools and missing workspace keys before packaging', () => {
  const directory = mkdtempSync(join(tmpdir(), 'nvpn-startos-preflight-'))
  const scripts = join(directory, 'package', 'scripts')
  const bin = join(directory, 'bin')
  const keyPath = join(directory, '.startos', 'build.key.pem')
  const invocationLog = join(directory, 'invocations')
  mkdirSync(scripts, { recursive: true })
  mkdirSync(bin)
  for (const name of ['startos-release.mjs', 'local-release-lib.mjs', 'release-artifact-provenance-lib.mjs', 'release-component-source.mjs']) {
    copyFileSync(new URL(name, import.meta.url), join(scripts, name))
  }
  const executable = join(bin, 'start-cli')
  writeFileSync(executable, `#!/bin/sh
printf '%s\\n' "$*" >> "$STARTOS_PREFLIGHT_LOG"
test "$1" = --version || exit 90
printf '%s\\n' "$STARTOS_PREFLIGHT_VERSION"
`)
  chmodSync(executable, 0o755)
  const run = (version, needsWorkspace = true) => spawnSync(process.execPath, [
    '--input-type=module', '-e',
    `import { preflightStartosRelease } from ${JSON.stringify(join(scripts, 'startos-release.mjs'))}; preflightStartosRelease({needsWorkspace: ${needsWorkspace}});`,
  ], {
    encoding: 'utf8',
    env: { ...process.env, PATH: `${bin}:${process.env.PATH}`, STARTOS_PREFLIGHT_LOG: invocationLog, STARTOS_PREFLIGHT_VERSION: version },
  })
  try {
    assert.match(run('start-cli 0.4.0-beta.9').stderr, /expected start-cli 1\.1\.0/)
    assert.match(run('start-cli 1.1.0').stderr, /Missing StartOS packaging workspace/)
    assert.equal(run('start-cli 1.1.0', false).status, 0)
    mkdirSync(join(directory, '.startos'))
    const key = generateKeyPairSync('ed25519').privateKey.export({ type: 'pkcs8', format: 'pem' })
    writeFileSync(keyPath, key, { mode: 0o600 })
    const ready = run('start-cli 1.1.0')
    assert.equal(ready.status, 0, ready.stderr)
    writeFileSync(keyPath, 'invalid key')
    assert.notEqual(run('start-cli 1.1.0').status, 0)
    assert.equal(readFileSync(invocationLog, 'utf8'), '--version\n'.repeat(5))
  } finally {
    rmSync(directory, { recursive: true, force: true })
  }
})

test('reused package inspection rejects an old CLI before reading its manifest', () => {
  const directory = mkdtempSync(join(tmpdir(), 'nvpn-startos-inspection-'))
  const invocationLog = join(directory, 'invocations')
  const executable = join(directory, 'start-cli')
  const sourceVersion = readStartosSourceVersion(readFileSync(
    new URL('../startos/versions/current.ts', import.meta.url), 'utf8',
  ))
  try {
    writeFileSync(executable, `#!/bin/sh
printf '%s\\n' "$*" >> "$STARTOS_INSPECTION_LOG"
if [ "$1" = --version ]; then
  printf 'start-cli 0.4.0-beta.9\\n'
else
  printf '{"id":"nostr-vpn","version":"${sourceVersion}","virtualNetworking":true,"images":[{"id":"app","arch":["x86_64"]}]}\\n'
fi
`)
    chmodSync(executable, 0o755)
    const result = spawnSync(process.execPath, ['--input-type=module', '-e', `
      import { inspectStartosReleasePackage } from ${JSON.stringify(new URL('./startos-release.mjs', import.meta.url).href)};
      inspectStartosReleasePackage({packagePath: 'fixture.s9pk', arch: 'x86_64', tag: ${JSON.stringify(`v${sourceVersion.split(':')[0]}`)}});
    `], {
      encoding: 'utf8',
      env: { ...process.env, PATH: `${directory}:${process.env.PATH}`, STARTOS_INSPECTION_LOG: invocationLog },
    })
    assert.notEqual(result.status, 0)
    assert.match(result.stderr, /expected start-cli 1\.1\.0/)
    assert.equal(readFileSync(invocationLog, 'utf8'), '--version\n')
  } finally {
    rmSync(directory, { recursive: true, force: true })
  }
})

test('resolveStartosTarget accepts make targets and architecture names', () => {
  assert.deepEqual(resolveStartosTarget('x86'), {
    arch: 'x86_64',
    makeTarget: 'x86',
  })
  assert.deepEqual(resolveStartosTarget('aarch64'), {
    arch: 'aarch64',
    makeTarget: 'arm',
  })
  assert.throws(() => resolveStartosTarget('riscv'), /Unsupported StartOS target/)
})

test('startosReleaseAssetName includes the release tag and architecture', () => {
  assert.equal(
    startosReleaseAssetName('4.0.97', 'x86_64'),
    'nostr-vpn-v4.0.97-startos-x86_64.s9pk',
  )
  assert.equal(
    startosReleaseAssetName('v4.0.97', 'aarch64'),
    'nostr-vpn-v4.0.97-startos-aarch64.s9pk',
  )
  assert.equal(
    startosReleaseAssetName('v4.1.4+4001006', 'aarch64'),
    'nostr-vpn-v4.1.4+4001006-startos-aarch64.s9pk',
  )
})

test('readStartosSourceVersion reads the SDK version graph source', () => {
  assert.equal(
    readStartosSourceVersion("export const currentVersion = VersionInfo.of({\n  version: '4.0.97:0',\n})\n"),
    '4.0.97:0',
  )
})

test('corrected tag build metadata stays separate from the StartOS revision', () => {
  assert.equal(expectedStartosVersion('v4.1.4+4001006', 1), '4.1.4:1')
  assert.equal(resolveStartosRevision('1', '4.1.4:0', 'v4.1.4+4001006'), 1)
  assert.equal(resolveStartosRevision('', '4.1.4:1', 'v4.1.4+4001006'), 1)
  assert.throws(
    () => resolveStartosRevision('', '4.1.3:1', 'v4.1.4+4001006'),
    /marketing version 4\.1\.3 does not match release v4\.1\.4\+4001006/,
  )
  assert.throws(() => resolveStartosRevision('100', '4.1.4:1', 'v4.1.4'), /revision/)
})

test('validateStartosManifest requires tunnel access, the v0.4 runtime, release version, and target image', () => {
  const manifest = {
    id: 'nostr-vpn',
    version: '4.0.97:0',
    virtualNetworking: true,
    images: [{ id: 'app', arch: ['x86_64'] }],
  }

  assert.doesNotThrow(() =>
    validateStartosManifest(manifest, { arch: 'x86_64', tag: 'v4.0.97' }),
  )
  assert.throws(
    () => validateStartosManifest(manifest, { arch: 'aarch64', tag: 'v4.0.97' }),
    /does not contain aarch64/,
  )
  assert.throws(
    () => validateStartosManifest(manifest, { arch: 'x86_64', tag: 'v4.0.98' }),
    /version 4\.0\.97:0 does not match release v4\.0\.98/,
  )
  assert.throws(
    () =>
      validateStartosManifest(
        { ...manifest, virtualNetworking: false },
        { arch: 'x86_64', tag: 'v4.0.97' },
      ),
    /virtualNetworking is false, expected true/,
  )

  const correctedManifest = { ...manifest, version: '4.1.4:1' }
  assert.doesNotThrow(() =>
    validateStartosManifest(correctedManifest, {
      arch: 'x86_64',
      tag: 'v4.1.4+4001006',
      revision: 1,
    }),
  )
})
