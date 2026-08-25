import test from 'node:test'
import assert from 'node:assert/strict'

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
