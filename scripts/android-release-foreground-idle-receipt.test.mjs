import test from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { spawnSync } from 'node:child_process'
import {
  existsSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

import {
  createAndroidForegroundIdleReceipt,
} from './android-release-foreground-idle-receipt.mjs'

const sha256 = (value) => createHash('sha256').update(value).digest('hex')

test('Android retry preserves old idle evidence before any new measurement', () => {
  const root = mkdtempSync(join(tmpdir(), 'nvpn-android-idle-retry-'))
  const raw = join(root, 'idle-cpu.json')
  const receipt = join(root, 'receipt.json')
  const prepare = () => spawnSync('/bin/bash', ['-c', `
    set -euo pipefail
    source "$TEST_LIBRARY"
    android_idle_cpu_path() { printf '%s\\n' "$TEST_RAW"; }
    android_release_prepare_idle_output
  `], {
    encoding: 'utf8',
    env: { ...process.env, TEST_RAW: raw, NVPN_ANDROID_FOREGROUND_IDLE_RECEIPT: receipt,
      TEST_LIBRARY: new URL('./lib-mobile-android-release-gate.sh', import.meta.url).pathname },
  })
  try {
    writeFileSync(raw, 'old raw sample')
    writeFileSync(receipt, 'old bound receipt')
    const result = prepare()
    assert.equal(result.status, 0, result.stderr)
    assert.equal(existsSync(raw), false)
    assert.equal(existsSync(receipt), false)
    const [archive] = readdirSync(root)
    assert.equal(readFileSync(join(root, archive, 'idle-cpu.json'), 'utf8'), 'old raw sample')
    assert.equal(readFileSync(join(root, archive, 'receipt.json'), 'utf8'), 'old bound receipt')
    assert.equal(prepare().status, 0)
    assert.equal(readdirSync(root).length, 1, 'empty retry creates no archive')
    writeFileSync(raw, 'new raw sample')
    symlinkSync(join(root, archive, 'receipt.json'), receipt)
    assert.notEqual(prepare().status, 0, 'symlink receipt must fail before moving raw evidence')
    assert.equal(readFileSync(raw, 'utf8'), 'new raw sample')
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('Release Android prepares idle outputs before touching the installed app', () => {
  const script = readFileSync(new URL('./mobile-android-smoke.sh', import.meta.url), 'utf8')
  assert.match(script, /if truthy "\$RELEASE_BLACKBOX_GATE"; then\s+if truthy "\$IDLE_CPU_GATE"; then\s+android_release_prepare_idle_output\s+fi\s+verify_android_release_install/)
})

function fixture(root) {
  const artifact = {
    receiptSchema: 2,
    artifactType: 'Android Release APK',
    appGitSha: 'a'.repeat(40),
    appGitTree: 'b'.repeat(40),
    fipsGitSha: 'c'.repeat(40),
    fipsGitTree: 'd'.repeat(40),
    apkSha256: '1'.repeat(64),
    installedApkSha256: '1'.repeat(64),
    package: 'fi.siriusbusiness.nvpn',
    signerCertificateSha256: '2'.repeat(64),
    companySigningVerified: true,
    debuggable: false,
  }
  const raw = {
    ok: true,
    mode: 'android-package',
    label: 'Android Release foreground VPN-off',
    maxPercent: 2,
    sampleSeconds: 60,
    settleSeconds: 10,
    elapsedSeconds: 60.2,
    cpuPercent: 1.4,
    package: artifact.package,
    pids: [1234],
    clockTicks: 100,
    generatedAt: '2026-08-09T17:30:55Z',
  }
  const artifactPath = join(root, 'artifact.json')
  const rawPath = join(root, 'idle-cpu.json')
  const outputPath = join(root, 'receipt.json')
  writeFileSync(artifactPath, `${JSON.stringify(artifact)}\n`)
  writeFileSync(rawPath, `${JSON.stringify(raw)}\n`)
  return { artifact, raw, artifactPath, rawPath, outputPath }
}

test('foreground-idle CLI writes evidence and rejects invalid commands through symlinked paths', () => {
  const root = mkdtempSync(join(tmpdir(), 'nvpn-android-idle-cli-'))
  try {
    const value = fixture(root)
    const script = fileURLToPath(new URL('./android-release-foreground-idle-receipt.mjs', import.meta.url))
    const scriptAlias = join(root, 'receipt-command.mjs')
    const directoryAlias = join(root, 'scripts')
    symlinkSync(script, scriptAlias)
    symlinkSync(dirname(script), directoryAlias, 'dir')
    for (const entry of [script, scriptAlias, join(directoryAlias, 'android-release-foreground-idle-receipt.mjs')]) {
      const invalid = spawnSync(process.execPath, [entry, 'invalid-command'], { encoding: 'utf8' })
      assert.equal(invalid.status, 1, `${entry}: ${invalid.stderr}`)
      assert.match(invalid.stderr, /usage:/)
      const result = spawnSync(process.execPath, [entry, 'create',
        '--artifact-receipt', value.artifactPath,
        '--raw-receipt', value.rawPath,
        '--output', value.outputPath,
        '--verified-live-context',
      ], { encoding: 'utf8' })
      assert.equal(result.status, 0, result.stderr)
      assert.match(result.stdout, /Android foreground-idle receipt:/)
      const receipt = JSON.parse(readFileSync(value.outputPath, 'utf8'))
      assert.equal(receipt.artifactReceiptSha256, sha256(readFileSync(value.artifactPath)))
      assert.equal(receipt.rawIdleCpuReceiptSha256, sha256(readFileSync(value.rawPath)))
      assert.deepEqual(receipt.sample, value.raw)
    }
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('live Android foreground-idle receipt binds the raw sample to the exact artifact', () => {
  const root = mkdtempSync(join(tmpdir(), 'nvpn-android-idle-receipt-'))
  try {
    const value = fixture(root)
    createAndroidForegroundIdleReceipt({
      artifactReceiptPath: value.artifactPath,
      rawReceiptPath: value.rawPath,
      outputPath: value.outputPath,
      verifiedLiveContext: true,
    })
    const receipt = JSON.parse(readFileSync(value.outputPath, 'utf8'))
    assert.equal(receipt.appGitSha, value.artifact.appGitSha)
    assert.equal(
      receipt.artifactReceiptSha256,
      sha256(readFileSync(value.artifactPath)),
    )
    assert.equal(
      receipt.rawIdleCpuReceiptSha256,
      sha256(readFileSync(value.rawPath)),
    )
    assert.deepEqual(receipt.sample, value.raw)
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('legacy Android foreground-idle evidence requires exact provenance and cleanup', () => {
  const root = mkdtempSync(join(tmpdir(), 'nvpn-android-idle-legacy-'))
  try {
    const value = fixture(root)
    const provenancePath = join(root, 'provenance.json')
    const summaryPath = join(root, 'summary.json')
    const cleanupPath = join(root, 'cleanup.json')
    const provenance = {
      appGitSha: value.artifact.appGitSha,
      appGitTree: value.artifact.appGitTree,
      fipsGitSha: value.artifact.fipsGitSha,
      fipsGitTree: value.artifact.fipsGitTree,
      apkSha256: value.artifact.apkSha256,
      package: value.artifact.package,
      signerCertificateSha256: value.artifact.signerCertificateSha256,
      companySigningVerified: true,
      installedApkByteIdentical: true,
      debuggable: false,
    }
    writeFileSync(provenancePath, `${JSON.stringify(provenance)}\n`)
    writeFileSync(summaryPath, `${JSON.stringify({
      ok: true,
      vpnMode: 'off',
      underlay: 'direct-validated-wifi',
      foregroundGateExitStatus: 0,
      foreground: value.raw,
    })}\n`)
    writeFileSync(cleanupPath, `${JSON.stringify({
      ok: true,
      appForceStopped: true,
      vpnInactive: true,
      directValidatedWifiRestored: true,
    })}\n`)

    const args = {
      artifactReceiptPath: value.artifactPath,
      rawReceiptPath: value.rawPath,
      outputPath: value.outputPath,
      legacyProvenancePath: provenancePath,
      legacySummaryPath: summaryPath,
      legacyCleanupPath: cleanupPath,
    }
    assert.doesNotThrow(() => createAndroidForegroundIdleReceipt(args))
    provenance.apkSha256 = '3'.repeat(64)
    writeFileSync(provenancePath, `${JSON.stringify(provenance)}\n`)
    assert.throws(
      () => createAndroidForegroundIdleReceipt(args),
      /legacy foreground-idle provenance differs from the exact artifact/i,
    )
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})
