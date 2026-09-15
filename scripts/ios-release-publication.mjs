import { spawnSync } from 'node:child_process'
import { isDeepStrictEqual } from 'node:util'
import {
  lstatSync,
  readFileSync,
  readdirSync,
  statSync,
} from 'node:fs'
import { join } from 'node:path'

import {
  captureIosUploadIntent,
  finalizeIosUploadReceipt,
  reconcileIosUploadReceipts,
  validateIosUploadReceipt,
  writeAcceptedIosPendingUpload,
  writeIosUploadIntent,
} from './ios-upload-receipt.mjs'
import {
  semverFromTag,
  sha256FileSync,
} from './local-release-lib.mjs'
import { withIosArtifactSource } from './ios-artifact-source.mjs'
import { requireReceiptSource } from './release-artifact-provenance-lib.mjs'

function exactFile(path, label) {
  const metadata = lstatSync(path)
  if (metadata.isSymbolicLink() || !metadata.isFile()) {
    throw new Error(`${label} must be a regular non-symlink file.`)
  }
  return metadata
}

function run(command, commandArgs, { cwd, env, capture = false } = {}) {
  const result = spawnSync(command, commandArgs, {
    cwd,
    env,
    encoding: 'utf8',
    stdio: capture ? 'pipe' : 'inherit',
  })
  if (result.status !== 0) {
    throw new Error(
      (capture ? result.stderr.trim() || result.stdout.trim() : '')
      || `${command} ${commandArgs.join(' ')} failed.`,
    )
  }
  return capture ? result.stdout.trim() : ''
}

function exactJson(path, label) {
  exactFile(path, label)
  try {
    const value = JSON.parse(readFileSync(path, 'utf8'))
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
      throw new Error('not a JSON object')
    }
    return value
  } catch (error) {
    throw new Error(`${label} is invalid: ${error.message}`)
  }
}

function exactIpaPath(repoRoot) {
  const directory = join(repoRoot, 'dist', 'ios', 'export')
  const names = readdirSync(directory)
    .filter((name) => name.endsWith('.ipa'))
    .sort()
  if (names.length !== 1) {
    throw new Error(
      `Expected exactly one frozen App Store IPA; found ${names.length}.`,
    )
  }
  const path = join(directory, names[0])
  exactFile(path, 'Frozen App Store IPA')
  return path
}

function normalizedGate(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('Staged release has no frozen iOS App Store gate.')
  }
  const keys = [
    'app_git_sha',
    'app_git_tree',
    'build_number',
    'bundle_id',
    'export_receipt_sha256',
    'ipa_sha256',
    'ipa_size',
    'marketing_version',
    'receipt_schema',
    'signer_certificate_sha256',
    'signing_team_id',
  ]
  const actualKeys = Object.keys(value).sort()
  const exactKeys = keys.sort()
  const proofKeys = [...keys, 'source_equivalence'].sort()
  if (
    JSON.stringify(actualKeys) !== JSON.stringify(exactKeys)
    && JSON.stringify(actualKeys) !== JSON.stringify(proofKeys)
  ) {
    throw new Error('Frozen iOS App Store gate fields are not exact.')
  }
  return value
}

export function validateFrozenIosPublication({ repoRoot, stagedManifest }) {
  const gate = normalizedGate(stagedManifest.ios_app_store_gate)
  const ipaPath = exactIpaPath(repoRoot)
  const receiptPath = join(
    repoRoot,
    'dist',
    'ios',
    'frozen',
    'app-store-receipt.json',
  )
  const receipt = exactJson(
    receiptPath,
    'Frozen iOS App Store export receipt',
  )
  const identity = receipt.identity ?? {}
  const signing = receipt.signing ?? {}
  const ipa = statSync(ipaPath)
  const sourceEquivalence = requireReceiptSource(receipt, {
    commit: stagedManifest.commit,
    tree: stagedManifest.release_gate_attestation?.app_git_tree,
    label: 'Frozen iOS App Store export receipt',
    candidateRoot: repoRoot,
    platform: 'ios',
  })
  if (
    gate.receipt_schema !== 1
    || !isDeepStrictEqual(
      gate.source_equivalence ?? null,
      sourceEquivalence,
    )
    || gate.marketing_version !== semverFromTag(stagedManifest.tag)
    || gate.bundle_id !== 'fi.siriusbusiness.nvpn'
    || !/^[1-9][0-9]*$/.test(String(gate.build_number ?? ''))
    || !/^[A-Z0-9]{10}$/.test(String(gate.signing_team_id ?? ''))
    || !/^[0-9a-f]{64}$/.test(
      String(gate.signer_certificate_sha256 ?? ''),
    )
    || !/^[0-9a-f]{64}$/.test(String(gate.ipa_sha256 ?? ''))
    || !/^[0-9a-f]{64}$/.test(
      String(gate.export_receipt_sha256 ?? ''),
    )
    || gate.ipa_size !== ipa.size
    || gate.ipa_sha256 !== sha256FileSync(ipaPath)
    || gate.export_receipt_sha256 !== sha256FileSync(receiptPath)
    || receipt.receiptSchema !== gate.receipt_schema
    || receipt.artifactType !== 'iOS export from frozen xcarchive'
    || receipt.distribution !== 'app-store-connect'
    || receipt.appGitSha !== gate.app_git_sha
    || receipt.appGitTree !== gate.app_git_tree
    || receipt.ipaSha256 !== gate.ipa_sha256
    || identity.appBundleIdentifier !== gate.bundle_id
    || identity.marketingVersion !== gate.marketing_version
    || String(identity.buildNumber) !== gate.build_number
    || identity.appBuildGitSha !== gate.app_git_sha
    || identity.packetTunnelBuildGitSha !== gate.app_git_sha
    || signing.signingTeamIdentifier !== gate.signing_team_id
    || signing.signerCertificateSha256
      !== gate.signer_certificate_sha256
  ) {
    throw new Error(
      'Frozen iOS App Store IPA or receipt differs from exact staging.',
    )
  }
  return { gate, ipaPath, receiptPath }
}

function parsePreflight(output, label) {
  const line = output.split(/\r?\n/).filter(Boolean).at(-1)
  try {
    const value = JSON.parse(line)
    if (!value || value.status !== 'passed') {
      throw new Error('status is not passed')
    }
    return value
  } catch (error) {
    throw new Error(`${label} returned invalid preflight evidence: ${error.message}`)
  }
}

function testflightPreflight({ repoRoot, mutationEnv }) {
  return parsePreflight(
    run(
      'bash',
      [join(repoRoot, 'scripts', 'testflight-internal'), 'preflight'],
      { cwd: repoRoot, env: mutationEnv, capture: true },
    ),
    'TestFlight',
  )
}

export function preflightIosPublication({
  repoRoot,
  stagedManifest,
  mutationEnv,
  dryRun = false,
}) {
  const frozen = validateFrozenIosPublication({
    repoRoot,
    stagedManifest,
  })
  if (dryRun) {
    return { ...frozen, buildPresent: false, dryRun: true }
  }
  if (!String(mutationEnv.NVPN_APPSTORE_REVIEW_WIREGUARD_CONFIG ?? '').trim()) {
    for (const name of [
      'NVPN_TESTFLIGHT_REVIEW_NOTES',
      'NVPN_APPSTORE_REVIEW_NOTES',
    ]) {
      if (!String(mutationEnv[name] ?? '').trim()) {
        throw new Error(
          `iOS publication requires a reviewer WireGuard configuration or complete review notes (${name}).`,
        )
      }
    }
  }
  const transporter =
    mutationEnv.NVPN_ITMS_TRANSPORTER
    || '/Applications/Transporter.app/Contents/itms/bin/iTMSTransporter'
  const transporterMetadata = exactFile(
    transporter,
    'Apple iTMSTransporter',
  )
  if ((transporterMetadata.mode & 0o111) === 0) {
    throw new Error(`Apple iTMSTransporter is not executable: ${transporter}`)
  }

  const testflight = testflightPreflight({ repoRoot, mutationEnv })
  const appStore = parsePreflight(
    run(
      'bash',
      [join(repoRoot, 'scripts', 'appstore-draft'), 'preflight'],
      { cwd: repoRoot, env: mutationEnv, capture: true },
    ),
    'App Store',
  )
  for (const evidence of [testflight, appStore]) {
    if (
      evidence.bundleId !== frozen.gate.bundle_id
      || evidence.version !== frozen.gate.marketing_version
      || String(evidence.buildNumber) !== frozen.gate.build_number
    ) {
      throw new Error('App Store Connect preflight differs from frozen iOS staging.')
    }
  }
  const receipts = reconcileIosUploadReceipts({
    repoRoot,
    frozen,
    stagedManifest,
    mutationEnv,
    testflight,
  })
  return {
    ...frozen,
    appStore,
    buildPresent: testflight.buildPresent === true,
    dryRun: false,
    ...receipts,
    testflight,
  }
}

export function publishExactIosDistribution({
  repoRoot,
  stagedManifest,
  mutationEnv,
  preflight,
  beforeMutation = () => {},
  dryRun = false,
}) {
  const frozen = validateFrozenIosPublication({ repoRoot, stagedManifest })
  if (dryRun) {
    return { submitted: false, verified: true }
  }
  if (
    !preflight
    || preflight.dryRun
    || preflight.gate?.ipa_sha256
      !== stagedManifest.ios_app_store_gate.ipa_sha256
  ) {
    throw new Error('iOS publication preflight does not bind exact staging.')
  }

  const runIosUpload = (command) => withIosArtifactSource({
    repoRoot,
    receipt: exactJson(frozen.receiptPath, 'Frozen iOS export receipt'),
    commit: stagedManifest.commit,
    tree: stagedManifest.release_gate_attestation?.app_git_tree,
    env: mutationEnv,
  }, (context) => run('bash', [join(repoRoot, 'scripts', 'ios-build'), command], context))

  let uploaded = preflight.testflight
  let receipts = {
    finalReceipt: preflight.finalReceipt,
    intentReceipt: preflight.intentReceipt,
    pendingReceipt: preflight.pendingReceipt,
    uploadAction: preflight.uploadAction,
  }
  const reconcile = () =>
    reconcileIosUploadReceipts({
      repoRoot,
      frozen,
      stagedManifest,
      mutationEnv,
      testflight: uploaded,
    })

  if (receipts.uploadAction === 'create-intent') {
    runIosUpload('ios-upload-preflight')
    const authorization = captureIosUploadIntent({
      repoRoot,
      frozen,
      stagedManifest,
      mutationEnv,
    })
    beforeMutation()
    const intent = writeIosUploadIntent({
      repoRoot,
      frozen,
      stagedManifest,
      mutationEnv,
      intent: authorization,
    })
    if (intent.created) {
      runIosUpload('ios-upload')
      writeAcceptedIosPendingUpload({
        repoRoot,
        frozen,
        stagedManifest,
        mutationEnv,
        intentReceipt: intent,
        acceptanceSource: 'transporter-returned',
      })
    } else {
      uploaded = testflightPreflight({ repoRoot, mutationEnv })
    }
    receipts = reconcile()
  }

  if (
    receipts.uploadAction === 'wait-intent'
    || receipts.uploadAction === 'wait-pending'
  ) {
    run(
      'bash',
      [join(repoRoot, 'scripts', 'testflight-internal'), 'wait'],
      { cwd: repoRoot, env: mutationEnv },
    )
    uploaded = testflightPreflight({ repoRoot, mutationEnv })
    receipts = reconcile()
  }

  if (receipts.uploadAction === 'recover-intent') {
    writeAcceptedIosPendingUpload({
      repoRoot,
      frozen,
      stagedManifest,
      mutationEnv,
      intentReceipt: receipts.intentReceipt,
      acceptanceSource: 'app-store-connect-visible',
    })
    receipts = reconcile()
  }
  if (receipts.uploadAction === 'finalize-pending') {
    finalizeIosUploadReceipt({
      repoRoot,
      frozen,
      stagedManifest,
      mutationEnv,
      pendingReceipt: receipts.pendingReceipt,
      testflight: uploaded,
    })
    receipts = reconcile()
  }
  if (receipts.uploadAction !== 'use-final') {
    throw new Error(
      'iOS upload journal did not reconcile to one exact VALID ASC build.',
    )
  }

  for (const [script, action] of [
    ['testflight-internal', 'put'],
    ['testflight-internal', 'public'],
  ]) {
    validateIosUploadReceipt({
      repoRoot,
      frozen,
      stagedManifest,
      mutationEnv,
      testflight: uploaded,
    })
    beforeMutation()
    run(
      'bash',
      [join(repoRoot, 'scripts', script), action],
      { cwd: repoRoot, env: mutationEnv },
    )
  }
  const submittedStates = new Set([
    'WAITING_FOR_REVIEW',
    'IN_REVIEW',
    'PENDING_APPLE_RELEASE',
    'PROCESSING_FOR_DISTRIBUTION',
    'READY_FOR_DISTRIBUTION',
    'READY_FOR_SALE',
  ])
  if (
    !submittedStates.has(preflight.appStore?.reviewState)
    && !submittedStates.has(preflight.appStore?.versionState)
  ) {
    beforeMutation()
    run(
      'bash',
      [join(repoRoot, 'scripts', 'appstore-draft'), 'submit'],
      { cwd: repoRoot, env: mutationEnv },
    )
  }
  for (const [script, action] of [
    ['testflight-internal', 'public-status'],
    ['appstore-draft', 'status'],
  ]) {
    run(
      'bash',
      [join(repoRoot, 'scripts', script), action],
      { cwd: repoRoot, env: mutationEnv },
    )
  }
  return { submitted: true, verified: true }
}
