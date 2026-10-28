import test from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { generateKeyPairSync } from 'node:crypto'
import { chmodSync, copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
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


test('StartOS helper is pinned before packing and drift deletes the package', () => {
  const makefile = readFileSync(new URL('../Makefile', import.meta.url), 'utf8')
  const pinned = makefile.match(/^STARTOS_UTILS_IMAGE := (\S+)$/m)?.[1]
  assert.match(pinned ?? '', /^ghcr\.io\/start9labs\/sdk\/utils@sha256:[a-f0-9]{64}$/)
  const directory = mkdtempSync(join(tmpdir(), 'nvpn-startos-helper-'))
  try {
    for (const scenario of ['ok', 'pull-failure', 'drift']) {
      const root = join(directory, scenario)
      const bin = join(root, 'bin')
      const log = join(root, 'commands')
      const drift = join(root, 'drifted')
      mkdirSync(bin, { recursive: true })
      mkdirSync(join(root, 'startos', 'manifest'), { recursive: true })
      writeFileSync(join(root, 'startos', 'manifest', 'index.ts'), "id: 'nostr-vpn',\n")
      for (const name of ['Makefile', 's9pk.mk']) {
        copyFileSync(new URL(`../${name}`, import.meta.url), join(root, name))
      }
      writeFileSync(join(bin, 'docker'), `#!/bin/sh
printf 'docker %s\\n' "$*" >> "$HELPER_LOG"
case "$1" in
  pull)
    test "$2" = "$HELPER_PIN" || exit 91
    test "$HELPER_CASE" != pull-failure || exit 92
    ;;
  tag)
    test "$2" = "$HELPER_PIN" || exit 93
    test "$3" = ghcr.io/start9labs/sdk/utils:latest || exit 94
    ;;
  image)
    test "$2" = inspect || exit 95
    if test "$3" = ghcr.io/start9labs/sdk/utils:latest && test -f "$HELPER_DRIFT"; then
      printf 'sha256:changed\\n'
    else
      printf 'sha256:pinned\\n'
    fi
    ;;
  *) exit 96 ;;
esac
`)
      writeFileSync(join(bin, 'start-cli'), `#!/bin/sh
if test "$1 $2" = 's9pk list-ingredients'; then exit 0; fi
test "$1 $2" = 's9pk pack' || exit 97
printf 'pack\\n' >> "$HELPER_LOG"
for output do :; done
printf fixture > "$output"
if test "$HELPER_CASE" = drift; then touch "$HELPER_DRIFT"; fi
`)
      chmodSync(join(bin, 'docker'), 0o755)
      chmodSync(join(bin, 'start-cli'), 0o755)
      const result = spawnSync('make', ['nostr-vpn_x86_64.s9pk'], {
        cwd: root, encoding: 'utf8',
        env: { ...process.env, PATH: `${bin}:${process.env.PATH}`, HELPER_PIN: pinned,
          HELPER_LOG: log, HELPER_DRIFT: drift, HELPER_CASE: scenario },
      })
      const commands = readFileSync(log, 'utf8').trim().split('\n')
      assert.equal(commands[0], `docker pull ${pinned}`)
      assert.equal(existsSync(join(root, 'nostr-vpn_x86_64.s9pk')), scenario === 'ok')
      if (scenario === 'ok') {
        assert.equal(result.status, 0, result.stderr)
        assert.equal(commands.filter((line) => line === 'pack').length, 1)
        assert.ok(commands.indexOf('pack') > commands.findIndex((line) => line.startsWith('docker image inspect')))
        assert.ok(commands.at(-1).startsWith('docker image inspect'))
      } else {
        assert.notEqual(result.status, 0)
        assert.equal(commands.includes('pack'), scenario === 'drift')
      }
    }
  } finally {
    rmSync(directory, { recursive: true, force: true })
  }
})
