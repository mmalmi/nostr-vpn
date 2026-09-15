#!/usr/bin/env node

import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { isAbsolute } from 'node:path'
import { pathToFileURL } from 'node:url'
import { isDeepStrictEqual } from 'node:util'

import {
  buildReleaseGateAttestation,
  collectReleaseGateReceipts,
  readRequiredJson,
  validateReleaseGateAttestation,
} from './release-artifact-provenance-lib.mjs'

const sha1 = /^[0-9a-f]{40}$/
const version = /^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$/
const sourceKeys = [
  'appGitSha',
  'appGitTree',
  'appVersion',
  'fipsGitSha',
  'fipsGitTree',
  'fipsVersion',
]
const platformReceiptKeys = {
  android: [
    'foreground_idle_cpu',
    'foreground_idle_cpu_raw',
    'install',
    'mobile_join',
    'physical',
    'replacement_singleton',
    'underlay_lifecycle',
    'wireguard_dns',
  ],
  ios: [
    'desktop_mobile_join',
    'frozen_archive',
    'join_variant',
    'mobile_artifact',
    'mobile_join',
    'underlay_lifecycle',
    'wireguard_dns',
  ],
  linux: [
    'arm64_cli',
    'artifact',
    'network',
    'package_install',
    'public_ui_join',
  ],
  macos: ['artifact', 'network_artifact', 'network', 'public_ui_join'],
  windows: ['artifact', 'installer', 'network', 'public_ui_join'],
}
const platformKeys = Object.keys(platformReceiptKeys).sort()

function requireObject(value, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} must be a JSON object.`)
  }
  return value
}

function requireExactKeys(value, expected, label) {
  requireObject(value, label)
  const actual = Object.keys(value).sort()
  const sortedExpected = [...expected].sort()
  if (
    actual.length !== sortedExpected.length ||
    actual.some((key, index) => key !== sortedExpected[index])
  ) {
    throw new Error(
      `${label} must contain exactly: ${sortedExpected.join(', ')}.`,
    )
  }
}

function requireSource(value) {
  requireExactKeys(value, sourceKeys, 'Release source')
  for (const field of [
    'appGitSha',
    'appGitTree',
    'fipsGitSha',
    'fipsGitTree',
  ]) {
    if (!sha1.test(String(value[field] ?? ''))) {
      throw new Error(`Release source ${field} is not an exact Git object ID.`)
    }
  }
  for (const field of ['appVersion', 'fipsVersion']) {
    if (!version.test(String(value[field] ?? ''))) {
      throw new Error(`Release source ${field} is not an exact version.`)
    }
  }
  return value
}

function requireAbsolutePath(value, label) {
  if (typeof value !== 'string' || !isAbsolute(value)) {
    throw new Error(`${label} must be an absolute path.`)
  }
  return value
}

function requireReceiptPathMap(value) {
  requireExactKeys(value, ['platforms', 'releaseGateSummary'], 'Receipt paths')
  requireAbsolutePath(
    value.releaseGateSummary,
    'Receipt paths releaseGateSummary',
  )
  requireExactKeys(value.platforms, platformKeys, 'Receipt path platforms')
  for (const platform of platformKeys) {
    const receipts = value.platforms[platform]
    requireExactKeys(
      receipts,
      platformReceiptKeys[platform],
      `${platform} receipt paths`,
    )
    for (const [name, path] of Object.entries(receipts)) {
      requireAbsolutePath(path, `${platform} receipt path ${name}`)
    }
  }
  return value
}

function requireAttestedReceiptKeys(attestation) {
  const receipts = attestation.platform_gate_receipts
  requireExactKeys(receipts, platformKeys, 'Attested receipt platforms')
  for (const platform of platformKeys) {
    requireExactKeys(
      receipts[platform],
      platformReceiptKeys[platform],
      `${platform} attested receipts`,
    )
  }
}

function requireExactFipsSource(receipt, source, label, versionField) {
  for (const [field, expected] of [
    ['fipsGitSha', source.fipsGitSha],
    ['fipsGitTree', source.fipsGitTree],
    [versionField, source.fipsVersion],
  ]) {
    if (receipt[field] !== expected) {
      throw new Error(`${label} has the wrong exact FIPS ${field}.`)
    }
  }
}

function requireCoreArtifactFipsSource(platformReceiptPaths, source) {
  for (const [platform, name, versionField] of [
    ['android', 'physical', 'fipsCoreVersion'],
    ['ios', 'mobile_artifact', 'fipsCoreVersion'],
    ['macos', 'artifact', 'fipsCoreVersion'],
    ['macos', 'network_artifact', 'fipsCoreVersion'],
    ['linux', 'artifact', 'fipsVersion'],
    ['windows', 'artifact', 'fipsVersion'],
  ]) {
    const receipt = readRequiredJson(
      platformReceiptPaths[platform][name],
      `${platform} core artifact receipt`,
    )
    requireExactFipsSource(
      receipt,
      source,
      `${platform} core artifact receipt`,
      versionField,
    )
  }
}

function requireAndroidGateComponentSource(
  manifest,
  platformReceiptPaths,
  source,
  platformSourceEquivalence,
) {
  const gate = requireObject(
    manifest.android_release_gate,
    'Staged Android release gate',
  )
  const physical = readRequiredJson(
    platformReceiptPaths.android.physical,
    'Physical Android artifact receipt',
  )
  const sourceEquivalence = platformSourceEquivalence.android
  const exactCandidate =
    gate.app_git_sha === source.appGitSha
    && gate.app_git_tree === source.appGitTree
    && !Object.hasOwn(gate, 'source_equivalence')
  const retainedCandidate =
    sourceEquivalence
    && isDeepStrictEqual(gate.source_equivalence, sourceEquivalence)
    && sourceEquivalence.receipt_app_git_sha === gate.app_git_sha
    && sourceEquivalence.receipt_app_git_tree === gate.app_git_tree
    && sourceEquivalence.candidate_app_git_sha === source.appGitSha
    && sourceEquivalence.candidate_app_git_tree === source.appGitTree
  if (
    gate.receipt_schema !== physical.receiptSchema
    || (!exactCandidate && !retainedCandidate)
    || gate.app_git_sha !== physical.appGitSha
    || gate.app_git_tree !== physical.appGitTree
    || gate.apk_sha256 !== physical.apkSha256
    || gate.package !== physical.package
    || gate.signer_certificate_sha256
      !== physical.signerCertificateSha256
  ) {
    throw new Error(
      'Staged Android release gate does not match the release candidate and physical receipt.',
    )
  }
}

function sha256File(path) {
  return createHash('sha256').update(readFileSync(path)).digest('hex')
}

function requireAttestedFileHashes(receiptPaths, attestation) {
  if (
    sha256File(receiptPaths.releaseGateSummary) !==
    attestation.release_gate_summary_sha256
  ) {
    throw new Error(
      'Release-gate summary hash differs from the staged attestation.',
    )
  }
  for (const platform of platformKeys) {
    for (const name of platformReceiptKeys[platform]) {
      if (
        sha256File(receiptPaths.platforms[platform][name]) !==
        attestation.platform_gate_receipts[platform][name]
      ) {
        throw new Error(
          `${platform} ${name} receipt hash differs from the staged attestation.`,
        )
      }
    }
  }
}

function requireReleaseIdentity(manifest, source) {
  const tag = `v${source.appVersion}`
  if (
    manifest.id !== tag ||
    manifest.tag !== tag ||
    manifest.title !== tag ||
    manifest.commit !== source.appGitSha
  ) {
    throw new Error(
      'Staged release identity does not match the exact release source.',
    )
  }
  if (typeof manifest.draft !== 'boolean') {
    throw new Error('Staged release draft must be a boolean.')
  }
  if (Object.hasOwn(manifest, 'passed') || Object.hasOwn(manifest, 'mocked')) {
    throw new Error(
      'Staged release cannot be replaced by a passed or mocked flag.',
    )
  }
}

function canonicalAttestation(manifest, source, attestation) {
  const canonical = buildReleaseGateAttestation({
    commit: source.appGitSha,
    tree: source.appGitTree,
    assets: manifest.assets,
    releaseGateSummarySha256: attestation.release_gate_summary_sha256,
    platformGateReceipts: attestation.platform_gate_receipts,
    platformSourceEquivalence: attestation.platform_source_equivalence,
    assetProofs: attestation.asset_proofs,
  })
  if (!isDeepStrictEqual(attestation, canonical)) {
    throw new Error(
      'Staged release-gate attestation is not the exact canonical schema.',
    )
  }
  return canonical
}

export function validateFleetReleaseGateEvidence(request) {
  requireExactKeys(
    request,
    ['candidateRoot', 'receiptPaths', 'releasePath', 'source'],
    'Fleet release-gate request',
  )
  const candidateRoot = requireAbsolutePath(
    request.candidateRoot,
    'Fleet release candidate root',
  )
  const releasePath = requireAbsolutePath(
    request.releasePath,
    'Fleet release path',
  )
  const source = requireSource(request.source)
  const receiptPaths = requireReceiptPathMap(request.receiptPaths)
  const manifest = readRequiredJson(releasePath, 'Staged release manifest')

  requireReleaseIdentity(manifest, source)
  const attestation = validateReleaseGateAttestation(manifest)
  if (attestation.app_git_tree !== source.appGitTree) {
    throw new Error(
      'Staged release-gate attestation has the wrong source tree.',
    )
  }
  requireAttestedReceiptKeys(attestation)
  const canonical = canonicalAttestation(manifest, source, attestation)

  readRequiredJson(
    receiptPaths.releaseGateSummary,
    'Release-gate completion receipt',
  )
  requireCoreArtifactFipsSource(receiptPaths.platforms, source)
  requireAttestedFileHashes(receiptPaths, canonical)

  const collected = collectReleaseGateReceipts({
    commit: source.appGitSha,
    tree: source.appGitTree,
    candidateRoot,
    releaseGateSummaryPath: receiptPaths.releaseGateSummary,
    platformReceiptPaths: receiptPaths.platforms,
  })
  requireAndroidGateComponentSource(
    manifest,
    receiptPaths.platforms,
    source,
    canonical.platform_source_equivalence,
  )
  if (
    collected.releaseGateSummarySha256 !==
      canonical.release_gate_summary_sha256 ||
    !isDeepStrictEqual(
      collected.platformGateReceipts,
      canonical.platform_gate_receipts,
    )
  ) {
    throw new Error(
      'Collected release-gate receipt hashes differ from the staged attestation.',
    )
  }
  if (!isDeepStrictEqual(
    collected.platformSourceEquivalence,
    canonical.platform_source_equivalence,
  )) {
    throw new Error(
      'Collected release-gate source equivalence differs from the staged attestation.',
    )
  }

  return {
    schema: 1,
    release: {
      id: manifest.id,
      tag: manifest.tag,
      title: manifest.title,
      commit: manifest.commit,
      draft: manifest.draft,
    },
    assets: manifest.assets
      .map(({ path, sha256, size }) => ({ path, sha256, size }))
      .sort((left, right) => left.path.localeCompare(right.path)),
    assetProofs: canonical.asset_proofs,
    assetSetSha256: canonical.asset_set_sha256,
    releaseGateSummarySha256: collected.releaseGateSummarySha256,
    platformGateReceipts: collected.platformGateReceipts,
  }
}

function main() {
  let request
  try {
    request = JSON.parse(readFileSync(0, 'utf8'))
  } catch {
    throw new Error('Fleet release-gate request on stdin is not valid JSON.')
  }
  process.stdout.write(
    `${JSON.stringify(validateFleetReleaseGateEvidence(request))}\n`,
  )
}

if (
  process.argv[1] &&
  pathToFileURL(process.argv[1]).href === import.meta.url
) {
  try {
    main()
  } catch (error) {
    process.stderr.write(
      `Fleet release-gate evidence rejected: ${error.message}\n`,
    )
    process.exitCode = 1
  }
}
