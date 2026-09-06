#!/usr/bin/env node

import { createHash } from 'node:crypto'
import {
  existsSync,
  linkSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  realpathSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { isDeepStrictEqual } from 'node:util'

import {
  validateAndroidForegroundIdleCpuSample,
} from './release-artifact-provenance-lib.mjs'

function fail(message) {
  throw new Error(message)
}

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex')
}

function readRegularJson(path, label) {
  if (!existsSync(path) || !lstatSync(path).isFile() || lstatSync(path).isSymbolicLink()) {
    fail(`${label} is not a regular file: ${path}`)
  }
  let value
  try {
    value = JSON.parse(readFileSync(path, 'utf8').replace(/^\uFEFF/, ''))
  } catch {
    fail(`${label} is not valid JSON: ${path}`)
  }
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    fail(`${label} is not a JSON object: ${path}`)
  }
  return value
}

function exactArtifactIdentity(artifact) {
  if (
    artifact.receiptSchema !== 2
    || artifact.artifactType !== 'Android Release APK'
    || artifact.companySigningVerified !== true
    || artifact.debuggable !== false
    || artifact.apkSha256 !== artifact.installedApkSha256
  ) {
    fail('Android foreground-idle artifact is not strict installed Release evidence.')
  }
  for (const field of ['appGitSha', 'appGitTree', 'fipsGitSha', 'fipsGitTree']) {
    if (!/^[0-9a-f]{40}$/.test(String(artifact[field] ?? ''))) {
      fail(`Android foreground-idle artifact has invalid ${field}.`)
    }
  }
  for (const field of [
    'apkSha256',
    'installedApkSha256',
    'signerCertificateSha256',
  ]) {
    if (!/^[0-9a-f]{64}$/.test(String(artifact[field] ?? ''))) {
      fail(`Android foreground-idle artifact has invalid ${field}.`)
    }
  }
  if (artifact.package !== 'fi.siriusbusiness.nvpn') {
    fail('Android foreground-idle artifact has the wrong package.')
  }
  return {
    apkSha256: artifact.apkSha256,
    installedApkSha256: artifact.installedApkSha256,
    package: artifact.package,
    signerCertificateSha256: artifact.signerCertificateSha256,
  }
}

function validateLegacyEvidence({
  artifact,
  rawReceipt,
  legacyProvenancePath,
  legacySummaryPath,
  legacyCleanupPath,
}) {
  const provenance = readRegularJson(
    legacyProvenancePath,
    'Legacy Android foreground-idle provenance',
  )
  const summary = readRegularJson(
    legacySummaryPath,
    'Legacy Android foreground-idle summary',
  )
  const cleanup = readRegularJson(
    legacyCleanupPath,
    'Legacy Android foreground-idle cleanup',
  )
  if (
    provenance.appGitSha !== artifact.appGitSha
    || provenance.appGitTree !== artifact.appGitTree
    || provenance.fipsGitSha !== artifact.fipsGitSha
    || provenance.fipsGitTree !== artifact.fipsGitTree
    || provenance.apkSha256 !== artifact.apkSha256
    || provenance.package !== artifact.package
    || provenance.signerCertificateSha256
      !== artifact.signerCertificateSha256
    || provenance.companySigningVerified !== true
    || provenance.installedApkByteIdentical !== true
    || provenance.debuggable !== false
  ) {
    fail('Legacy foreground-idle provenance differs from the exact artifact.')
  }
  if (
    summary.ok !== true
    || summary.vpnMode !== 'off'
    || summary.underlay !== 'direct-validated-wifi'
    || summary.foregroundGateExitStatus !== 0
    || !isDeepStrictEqual(summary.foreground, rawReceipt)
    || cleanup.ok !== true
    || cleanup.appForceStopped !== true
    || cleanup.vpnInactive !== true
    || cleanup.directValidatedWifiRestored !== true
  ) {
    fail('Legacy foreground-idle context or cleanup is incomplete.')
  }
}

function writeExclusiveJson(path, value) {
  const bytes = `${JSON.stringify(value, null, 2)}\n`
  if (existsSync(path)) {
    if (
      lstatSync(path).isFile()
      && !lstatSync(path).isSymbolicLink()
      && readFileSync(path, 'utf8') === bytes
    ) {
      return
    }
    fail(`Android foreground-idle receipt output already exists: ${path}`)
  }
  mkdirSync(dirname(path), { recursive: true })
  const temporary = `${path}.tmp.${process.pid}`
  writeFileSync(temporary, bytes, { flag: 'wx' })
  try {
    linkSync(temporary, path)
  } finally {
    unlinkSync(temporary)
  }
}

export function createAndroidForegroundIdleReceipt({
  artifactReceiptPath,
  rawReceiptPath,
  outputPath,
  verifiedLiveContext = false,
  legacyProvenancePath = '',
  legacySummaryPath = '',
  legacyCleanupPath = '',
}) {
  const artifactBytes = readFileSync(artifactReceiptPath)
  const rawReceiptBytes = readFileSync(rawReceiptPath)
  const artifact = readRegularJson(
    artifactReceiptPath,
    'Android foreground-idle artifact receipt',
  )
  const rawReceipt = readRegularJson(
    rawReceiptPath,
    'Android foreground-idle raw CPU receipt',
  )
  const identity = exactArtifactIdentity(artifact)
  validateAndroidForegroundIdleCpuSample(rawReceipt, artifact.package)

  const legacyPaths = [
    legacyProvenancePath,
    legacySummaryPath,
    legacyCleanupPath,
  ]
  const hasCompleteLegacyEvidence = legacyPaths.every(Boolean)
  if (
    (verifiedLiveContext && legacyPaths.some(Boolean))
    || (!verifiedLiveContext && !hasCompleteLegacyEvidence)
  ) {
    fail(
      'Android foreground-idle receipt requires either verified live context or all legacy evidence files.',
    )
  }
  if (hasCompleteLegacyEvidence) {
    validateLegacyEvidence({
      artifact,
      rawReceipt,
      legacyProvenancePath,
      legacySummaryPath,
      legacyCleanupPath,
    })
  }

  const receipt = {
    receiptSchema: 1,
    artifactType: 'Android exact Release foreground VPN-off idle CPU gate',
    platform: 'android',
    mode: 'foreground-vpn-off-idle',
    appGitSha: artifact.appGitSha,
    appGitTree: artifact.appGitTree,
    fipsGitSha: artifact.fipsGitSha,
    fipsGitTree: artifact.fipsGitTree,
    artifactReceiptSha256: sha256(artifactBytes),
    artifactIdentity: identity,
    rawIdleCpuReceiptSha256: sha256(rawReceiptBytes),
    foregroundActivityVerified: true,
    vpnInactiveBeforeSample: true,
    releaseNonDebuggable: true,
    sample: rawReceipt,
  }
  writeExclusiveJson(outputPath, receipt)
  return receipt
}

function parseArgs(argv) {
  if (argv[0] !== 'create') {
    fail('usage: android-release-foreground-idle-receipt.mjs create [options]')
  }
  const result = {}
  for (let index = 1; index < argv.length; index += 1) {
    const name = argv[index]
    if (name === '--verified-live-context') {
      result.verifiedLiveContext = true
      continue
    }
    const value = argv[++index]
    if (!value) fail(`Missing value for ${name}.`)
    const key = {
      '--artifact-receipt': 'artifactReceiptPath',
      '--raw-receipt': 'rawReceiptPath',
      '--output': 'outputPath',
      '--legacy-provenance': 'legacyProvenancePath',
      '--legacy-summary': 'legacySummaryPath',
      '--legacy-cleanup': 'legacyCleanupPath',
    }[name]
    if (!key) fail(`Unknown option: ${name}`)
    result[key] = resolve(value)
  }
  for (const key of ['artifactReceiptPath', 'rawReceiptPath', 'outputPath']) {
    if (!result[key]) fail(`Missing required ${key}.`)
  }
  return result
}

if (process.argv[1] && realpathSync(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const options = parseArgs(process.argv.slice(2))
    createAndroidForegroundIdleReceipt(options)
    console.log(`Android foreground-idle receipt: ${options.outputPath}`)
  } catch (error) {
    console.error(error.message)
    process.exitCode = 1
  }
}
