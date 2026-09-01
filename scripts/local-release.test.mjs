import test from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import {
  chmodSync,
  copyFileSync,
  mkdtempSync,
  mkdirSync,
  readFileSync,
  rmSync,
  statSync,
  symlinkSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'

import {
  androidReleaseAssetName,
  androidVersionCode,
  autoDetectWindowsVmName,
  buildReleaseManifestFiles,
  buildReleaseManifest,
  bumpAndroidGradleVersion,
  bumpCargoPackageVersion,
  bumpPbxprojMarketingVersion,
  bumpStartosSourceVersion,
  deterministicBuildEnv,
  describeAsset,
  extractChangelogSection,
  linuxReleaseTargetsForDockerPlatform,
  parseEnvFile,
  readWorkspaceVersionTag,
  replaceWithExactFileCopy,
  renderReleaseNotes,
  semverFromTag,
  shouldBlockLocalLinuxAmd64Qemu,
  splitCsv,
  validateAndroidBundleRelationship,
  validateAndroidReleaseGateReceipt,
  validateCleanReleaseSource,
  validateMacosGateSigningIdentity,
  validatePromotableReleaseManifest,
  validatePromotableReleaseSource,
  validateReleaseAssetSet,
  validateStagedReleaseTree,
  validateZapstoreApkMetadata,
  validateZapstoreRelayPublication,
  windowsSshTransportArgs,
  zapstorePublicationPrerequisites,
  zapstorePublicationRequired,
} from './local-release-lib.mjs'
import {
  githubRepositoryFromRemote,
  githubReleaseRepairPlan,
  validateGithubReleaseMetadata,
} from './github-release-publication.mjs'
import { parseActiveHtreeIdentity } from './htree-release-publication.mjs'
import {
  validateFrozenIosPublication,
} from './ios-release-publication.mjs'
import {
  captureIosUploadIntent,
  finalizeIosUploadReceipt,
  planIosUploadReconciliation,
  reconcileIosUploadReceipts,
  validateIosPendingUploadReceipt,
  validateIosUploadReceipt,
  writeAcceptedIosPendingUpload,
  writeIosUploadIntent,
} from './ios-upload-receipt.mjs'
import {
  assertRealStageDirectory,
  validateReleaseMutationGate,
} from './release-mutation-gate.mjs'
import { resolveSignWith } from './zapstore-release-publication.mjs'
import {
  buildReleaseGateAttestation,
  releaseAssetSetSha256,
  startosExactPackageValidator,
  validateReleaseGateAttestation,
} from './release-artifact-provenance-lib.mjs'
import { proveUnchangedPlatformInputs } from './release-component-source.mjs'

test('parseEnvFile reads basic dotenv syntax', () => {
  const parsed = parseEnvFile(`
# comment
NVPN_RELEASE_TREE=releases/nostr-vpn
NVPN_WINDOWS_VM_NAME="Windows 11"
NVPN_NOTE='line one'
INVALID KEY=nope
`)

  assert.deepEqual(parsed, {
    NVPN_RELEASE_TREE: 'releases/nostr-vpn',
    NVPN_WINDOWS_VM_NAME: 'Windows 11',
    NVPN_NOTE: 'line one',
  })
})

test('GitHub publication derives one explicit repository from the github remote', () => {
  for (const remote of [
    'git@github.com:mmalmi/nostr-vpn.git',
    'ssh://git@github.com/mmalmi/nostr-vpn.git',
    'https://github.com/mmalmi/nostr-vpn.git',
  ]) {
    assert.equal(githubRepositoryFromRemote(remote), 'mmalmi/nostr-vpn')
  }
  for (const remote of [
    '',
    'git@example.com:mmalmi/nostr-vpn.git',
    'https://github.com/mmalmi/nostr-vpn/extra',
    'mmalmi/nostr-vpn',
  ]) {
    assert.throws(
      () => githubRepositoryFromRemote(remote),
      /exact github\.com owner\/repository URL/,
    )
  }
})

test('splitCsv trims and drops empties', () => {
  assert.deepEqual(splitCsv('verify, windows,android ,, macos'), [
    'verify',
    'windows',
    'android',
    'macos',
  ])
})

test('htree identity parser accepts current and legacy active identity output', () => {
  const npub = `npub1${'q'.repeat(58)}`
  assert.equal(
    parseActiveHtreeIdentity(`${npub}\n\nAliases:\n${npub} (sirius)`),
    npub,
  )
  assert.equal(parseActiveHtreeIdentity(`${npub} (self)`), npub)
  assert.throws(
    () => parseActiveHtreeIdentity(`${npub} (self)\n${npub} (self)`),
    /exactly one valid active identity/,
  )
})

test('release source provenance rejects dirty or mismatched tagged candidates', () => {
  const commit = 'a'.repeat(40)
  assert.equal(
    validateCleanReleaseSource({
      status: '',
      headCommit: commit,
      taggedCommit: commit,
      tag: 'v4.1.4+4001006',
    }),
    commit,
  )
  assert.throws(
    () => validateCleanReleaseSource({
      status: ' M ios/Sources/AppModel.swift',
      headCommit: commit,
    }),
    /source is dirty/i,
  )
  assert.throws(
    () => validateCleanReleaseSource({
      status: '',
      headCommit: commit,
      taggedCommit: 'b'.repeat(40),
      tag: 'v4.1.4+4001006',
    }),
    /points to .* not candidate HEAD/i,
  )
})

test('draft promotion requires one clean commit across source, tag, and manifest', () => {
  const commit = 'a'.repeat(40)
  const manifest = {
    id: 'v4.1.5',
    title: 'v4.1.5',
    tag: 'v4.1.5',
    commit,
    draft: true,
  }
  const context = {
    manifest,
    requestedTag: 'v4.1.5',
    workspaceTag: 'v4.1.5',
    status: '',
    headCommit: commit,
    taggedCommit: commit,
  }

  assert.equal(validatePromotableReleaseSource(context), commit)
  for (const [override, message] of [
    [{ status: ' M Cargo.lock' }, /source is dirty/i],
    [{ headCommit: 'b'.repeat(40) }, /staged manifest commit/i],
    [{ taggedCommit: '' }, /release tag .* does not exist/i],
    [{ taggedCommit: 'c'.repeat(40) }, /release tag .* not staged commit/i],
    [{ requestedTag: 'v4.1.6' }, /requested tag .* staged manifest/i],
    [{ workspaceTag: 'v4.1.6' }, /workspace version .* staged manifest/i],
    [{ manifest: { ...manifest, id: 'v4.1.4' } }, /manifest identity fields/i],
    [{ manifest: { ...manifest, draft: false } }, /not a draft/i],
  ]) {
    assert.throws(
      () => validatePromotableReleaseSource({ ...context, ...override }),
      message,
    )
  }
})

test('Android publication accepts only the exact signed APK sealed by the physical gate', () => {
  const apkSha256 = 'a'.repeat(64)
  const aabSha256 = '9'.repeat(64)
  const pathSha256 = 'b'.repeat(64)
  const appGitSha = 'c'.repeat(40)
  const appGitTree = 'd'.repeat(40)
  const packageId = 'fi.siriusbusiness.nvpn'
  const receipt = {
    receiptSchema: 2,
    artifactType: 'Android Release APK',
    apkPathSha256: pathSha256,
    apkSha256,
    installedApkSha256: apkSha256,
    aabSha256,
    apkDerivedFromAab: true,
    bundleReceiptSha256: '8'.repeat(64),
    bundletoolVersion: '1.18.3',
    bundletoolSha256:
      'a099cfa1543f55593bc2ed16a70a7c67fe54b1747bb7301f37fdfd6d91028e29',
    companySigningVerified: true,
    signerCertificateSha256: 'e'.repeat(64),
    appGitSha,
    appGitTree,
    package: packageId,
    replacementInstall: true,
    debuggable: false,
  }
  const context = {
    apkSha256,
    aabSha256,
    expectedAppGitSha: appGitSha,
    expectedAppGitTree: appGitTree,
    expectedPackage: packageId,
  }

  assert.deepEqual(validateAndroidReleaseGateReceipt(receipt, context), {
    receiptSchema: 2,
    apkSha256,
    aabSha256,
    appGitSha,
    appGitTree,
    package: packageId,
    signerCertificateSha256: 'e'.repeat(64),
  })
  for (const [override, message] of [
    [{ apkSha256: 'f'.repeat(64) }, /APK bytes.*physical gate/i],
    [{ aabSha256: 'f'.repeat(64) }, /exact Play AAB/i],
    [{ expectedAppGitSha: 'f'.repeat(40) }, /application commit/i],
    [{ expectedAppGitTree: 'f'.repeat(40) }, /application tree/i],
    [{ expectedPackage: 'example.invalid' }, /package/i],
    [{}, /signed/i],
  ]) {
    const candidateReceipt =
      Object.keys(override).length === 0
        ? { ...receipt, companySigningVerified: false }
        : receipt
    assert.throws(
      () => validateAndroidReleaseGateReceipt(
        candidateReceipt,
        { ...context, ...override },
      ),
      message,
    )
  }
  assert.throws(
    () => validateAndroidReleaseGateReceipt(
      { ...receipt, apkPathSha256: 'not-a-hash' },
      context,
    ),
    /historical APK path hash/i,
  )
  assert.throws(
    () => validateAndroidReleaseGateReceipt(
      { ...receipt, apkDerivedFromAab: false },
      context,
    ),
    /exact Play AAB/i,
  )
  assert.throws(
    () => validateAndroidReleaseGateReceipt(
      { ...receipt, installedApkSha256: 'f'.repeat(64) },
      context,
    ),
    /installed APK.*tested artifact/i,
  )
  assert.throws(
    () => validateAndroidReleaseGateReceipt(
      { ...receipt, debuggable: true },
      context,
    ),
    /debuggable/i,
  )
  assert.throws(
    () => validateAndroidReleaseGateReceipt(
      { ...receipt, appGitSha: 'not-a-commit' },
      { ...context, expectedAppGitSha: 'not-a-commit' },
    ),
    /component-origin SHA\/tree/i,
  )

  const bundleReceipt = {
    schema: 1,
    relationship: 'universal-apk-derived-from-exact-aab',
    appGitSha,
    appGitTree,
    apkSha256,
    aabSha256,
    apkPathSha256: pathSha256,
    aabPathSha256: '7'.repeat(64),
    bundletoolVersion: receipt.bundletoolVersion,
    bundletoolSha256: receipt.bundletoolSha256,
  }
  const relationship = {
    receipt,
    receiptSha256: receipt.bundleReceiptSha256,
    apkSha256,
    aabSha256,
  }
  assert.doesNotThrow(() =>
    validateAndroidBundleRelationship(bundleReceipt, relationship),
  )
  for (const [candidate, candidateContext] of [
    [{ ...bundleReceipt, apkPathSha256: '7'.repeat(64) }, relationship],
    [bundleReceipt, { ...relationship, receiptSha256: '6'.repeat(64) }],
  ]) {
    assert.throws(
      () => validateAndroidBundleRelationship(candidate, candidateContext),
      /bundle relationship sealed by the physical gate/i,
    )
  }
})

test('macOS publication selects the exact gated leaf when another Developer ID identity is first', () => {
  const signingIdentitySha1 = 'a'.repeat(40)
  const signingTeam = 'ABCDEFGHIJ'
  const signerCertificateSha256 = 'b'.repeat(64)
  const receipt = {
    receiptSchema: 1,
    artifactType: 'macOS company Developer ID Release gate package',
    companySigningVerified: true,
    signingIdentitySha1,
    signingTeam,
    signerCertificateSha256,
  }
  const identities = [
    `  1) ${'C'.repeat(40)} "Developer ID Application: Unrelated (KLMNOPQRST)"`,
    `  2) ${signingIdentitySha1.toUpperCase()} "Developer ID Application: Expected (${signingTeam})"`,
    '     2 valid identities found',
  ].join('\n')

  assert.deepEqual(
    validateMacosGateSigningIdentity({
      receipt,
      codesigningIdentities: identities,
      resolvedCertificateSha256: signerCertificateSha256,
    }),
    {
      identitySha1: signingIdentitySha1.toUpperCase(),
      signingTeam,
      signerCertificateSha256,
    },
  )
  assert.throws(
    () => validateMacosGateSigningIdentity({
      receipt,
      codesigningIdentities: identities,
      resolvedCertificateSha256: 'd'.repeat(64),
    }),
    /certificate differs from the gate receipt/i,
  )
  assert.throws(
    () => validateMacosGateSigningIdentity({
      receipt: { ...receipt, signingTeam: 'KLMNOPQRST' },
      codesigningIdentities: identities,
      resolvedCertificateSha256: signerCertificateSha256,
    }),
    /team differs from the gate receipt/i,
  )
})

test('Zapstore publication can be made mandatory by CLI or release environment', () => {
  assert.equal(zapstorePublicationRequired({ cliRequired: true }), true)
  assert.equal(
    zapstorePublicationRequired({ envValue: 'true' }),
    true,
  )
  assert.equal(
    zapstorePublicationRequired({ envValue: '0' }),
    false,
  )
})

test('required Zapstore mode rejects every missing publication prerequisite', () => {
  const complete = {
    apk: true,
    zsp: true,
    nak: true,
    signing: true,
    config: true,
    publisher: true,
    relays: true,
  }
  assert.deepEqual(
    zapstorePublicationPrerequisites(complete, { required: true }),
    { available: true, missing: [] },
  )

  for (const prerequisite of Object.keys(complete)) {
    assert.throws(
      () =>
        zapstorePublicationPrerequisites(
          { ...complete, [prerequisite]: false },
          { required: true },
        ),
      new RegExp(`Required Zapstore publication unavailable:.*${prerequisite}`, 'i'),
    )
  }

  const optional = zapstorePublicationPrerequisites(
    { ...complete, signing: false },
  )
  assert.equal(optional.available, false)
  assert.match(optional.missing[0], /signing/i)
})

test('Zapstore signing identity comes only from the sealed publication environment', () => {
  const ambient = process.env.SIGN_WITH
  process.env.SIGN_WITH = 'ambient-substitution'
  try {
    assert.equal(resolveSignWith({ SIGN_WITH: 'sealed-identity' }), 'sealed-identity')
    assert.equal(resolveSignWith({}), '')
  } finally {
    if (ambient === undefined) {
      delete process.env.SIGN_WITH
    } else {
      process.env.SIGN_WITH = ambient
    }
  }
})

test('required Zapstore APK metadata proves version, package, ABI, and Android signing', () => {
  assert.deepEqual(
    validateZapstoreApkMetadata(
      {
        package_id: 'fi.siriusbusiness.nvpn',
        version_name: '4.1.4',
        version_code: 4_010_401,
        sha256: 'c'.repeat(64),
        architectures: ['arm64-v8a'],
        cert_fingerprint: 'abcdef',
      },
      {
        expectedVersion: '4.1.4',
        expectedVersionCode: 4_010_401,
        expectedPackageId: 'fi.siriusbusiness.nvpn',
        expectedCertificateFingerprint: 'abcdef',
      },
    ),
    {
      packageId: 'fi.siriusbusiness.nvpn',
      versionName: '4.1.4',
      versionCode: 4_010_401,
      certificateFingerprint: 'abcdef',
      sha256: 'c'.repeat(64),
    },
  )

  for (const [field, value, message] of [
    ['version_name', '4.1.3', /version/],
    ['version_code', 4_010_400, /version code/],
    ['package_id', 'com.example.wrong', /package/],
    ['architectures', ['x86_64'], /arm64-v8a/],
    ['cert_fingerprint', '', /signed/],
    ['sha256', 'not-a-hash', /SHA-256/],
  ]) {
    const metadata = {
      package_id: 'fi.siriusbusiness.nvpn',
      version_name: '4.1.4',
      version_code: 4_010_401,
      sha256: 'c'.repeat(64),
      architectures: ['arm64-v8a'],
      cert_fingerprint: 'abcdef',
      [field]: value,
    }
    assert.throws(
      () =>
        validateZapstoreApkMetadata(metadata, {
          expectedVersion: '4.1.4',
          expectedVersionCode: 4_010_401,
          expectedPackageId: 'fi.siriusbusiness.nvpn',
          expectedCertificateFingerprint: 'abcdef',
        }),
      message,
    )
  }
  assert.throws(
    () =>
      validateZapstoreApkMetadata(
        {
          package_id: 'fi.siriusbusiness.nvpn',
          version_name: '4.1.4',
          version_code: 4_010_401,
          sha256: 'c'.repeat(64),
          architectures: ['arm64-v8a'],
          cert_fingerprint: 'abcdef',
        },
        {
          expectedVersion: '4.1.4',
          expectedVersionCode: 4_010_401,
          expectedPackageId: 'fi.siriusbusiness.nvpn',
          expectedCertificateFingerprint: '123456',
        },
      ),
    /certificate/i,
  )
})

test('required Zapstore verification accepts only exact signed relay events', () => {
  const pubkey = 'a'.repeat(64)
  const asset = {
    kind: 3063,
    id: 'b'.repeat(64),
    pubkey,
    tags: [
      ['i', 'fi.siriusbusiness.nvpn'],
      ['version', '4.1.4'],
      ['version_code', '4010401'],
      ['x', 'c'.repeat(64)],
      ['apk_certificate_hash', 'abcdef'],
      ['f', 'android-arm64-v8a'],
      ['url', 'https://cdn.example/app.apk'],
    ],
  }
  const release = {
    kind: 30063,
    id: 'd'.repeat(64),
    pubkey,
    tags: [
      ['i', 'fi.siriusbusiness.nvpn'],
      ['version', '4.1.4'],
      ['d', 'fi.siriusbusiness.nvpn@4.1.4'],
      ['c', 'main'],
      ['f', 'android-arm64-v8a'],
      ['e', asset.id],
    ],
  }
  const app = {
    kind: 32267,
    id: 'e'.repeat(64),
    pubkey,
    tags: [
      ['d', 'fi.siriusbusiness.nvpn'],
      ['f', 'android-arm64-v8a'],
    ],
  }

  assert.deepEqual(
    validateZapstoreRelayPublication({
      appEvents: [app],
      releaseEvents: [release],
      assetEvents: [asset],
      expected: {
        pubkey,
        packageId: 'fi.siriusbusiness.nvpn',
        versionName: '4.1.4',
        versionCode: 4_010_401,
        sha256: 'c'.repeat(64),
        certificateFingerprint: 'abcdef',
      },
    }),
    { app, release, asset },
  )

  const wrongAsset = structuredClone(asset)
  wrongAsset.tags = wrongAsset.tags.map((tag) =>
    tag[0] === 'x' ? ['x', 'f'.repeat(64)] : tag
  )
  assert.throws(
    () =>
      validateZapstoreRelayPublication({
        appEvents: [app],
        releaseEvents: [release],
        assetEvents: [wrongAsset],
        expected: {
          pubkey,
          packageId: 'fi.siriusbusiness.nvpn',
          versionName: '4.1.4',
          versionCode: 4_010_401,
          sha256: 'c'.repeat(64),
          certificateFingerprint: 'abcdef',
        },
      }),
    /software asset/,
  )
})

test('frozen iOS publication rejects IPA, receipt, signer, and source substitution', () => {
  const repoRoot = mkdtempSync(join(tmpdir(), 'nvpn-ios-publication-'))
  const exportDir = join(repoRoot, 'dist', 'ios', 'export')
  const frozenDir = join(repoRoot, 'dist', 'ios', 'frozen')
  mkdirSync(exportDir, { recursive: true })
  mkdirSync(frozenDir, { recursive: true })
  const ipaPath = join(exportDir, 'NostrVpnIos.ipa')
  const receiptPath = join(frozenDir, 'app-store-receipt.json')
  writeFileSync(ipaPath, 'exact frozen ipa bytes')
  const ipaSha256 = createHash('sha256')
    .update(readFileSync(ipaPath))
    .digest('hex')
  const commit = '1'.repeat(40)
  const tree = '2'.repeat(40)
  const signer = '3'.repeat(64)
  const receipt = {
    receiptSchema: 1,
    artifactType: 'iOS export from frozen xcarchive',
    distribution: 'app-store-connect',
    appGitSha: commit,
    appGitTree: tree,
    ipaSha256,
    identity: {
      appBundleIdentifier: 'fi.siriusbusiness.nvpn',
      appBuildGitSha: commit,
      buildNumber: '4010501',
      marketingVersion: '4.1.5',
      packetTunnelBuildGitSha: commit,
    },
    signing: {
      signerCertificateSha256: signer,
      signingTeamIdentifier: 'ABCDEFGHIJ',
    },
  }
  writeFileSync(receiptPath, `${JSON.stringify(receipt)}\n`)
  const receiptSha256 = createHash('sha256')
    .update(readFileSync(receiptPath))
    .digest('hex')
  const stagedManifest = {
    tag: 'v4.1.5',
    commit,
    release_gate_attestation: { app_git_tree: tree },
    ios_app_store_gate: {
      receipt_schema: 1,
      app_git_sha: commit,
      app_git_tree: tree,
      bundle_id: 'fi.siriusbusiness.nvpn',
      marketing_version: '4.1.5',
      build_number: '4010501',
      ipa_sha256: ipaSha256,
      ipa_size: statSync(ipaPath).size,
      export_receipt_sha256: receiptSha256,
      signing_team_id: 'ABCDEFGHIJ',
      signer_certificate_sha256: signer,
      source_equivalence: null,
    },
  }
  assert.equal(
    validateFrozenIosPublication({ repoRoot, stagedManifest }).ipaPath,
    ipaPath,
  )

  writeFileSync(ipaPath, 'substituted ipa bytes')
  assert.throws(
    () => validateFrozenIosPublication({ repoRoot, stagedManifest }),
    /differs from exact staging/i,
  )
  writeFileSync(ipaPath, 'exact frozen ipa bytes')

  writeFileSync(
    receiptPath,
    `${JSON.stringify({
      ...receipt,
      signing: {
        ...receipt.signing,
        signerCertificateSha256: '4'.repeat(64),
      },
    })}\n`,
  )
  assert.throws(
    () => validateFrozenIosPublication({ repoRoot, stagedManifest }),
    /differs from exact staging/i,
  )
  writeFileSync(receiptPath, `${JSON.stringify(receipt)}\n`)

  assert.throws(
    () =>
      validateFrozenIosPublication({
        repoRoot,
        stagedManifest: {
          ...stagedManifest,
          commit: '5'.repeat(40),
        },
      }),
    /differs from exact staging|receipt source lookup/i,
  )
})

test('frozen iOS publication binds an unchanged-product source proof', () => {
  const repoRoot = mkdtempSync(join(tmpdir(), 'nvpn-ios-publication-source-'))
  const git = (...args) => {
    const result = spawnSync('git', args, { cwd: repoRoot, encoding: 'utf8' })
    assert.equal(result.status, 0, result.stderr)
    return result.stdout.trim()
  }
  git('init', '-q')
  git('config', 'user.name', 'Release Test')
  git('config', 'user.email', 'release@example.invalid')
  mkdirSync(join(repoRoot, 'ios', 'Sources'), { recursive: true })
  mkdirSync(join(repoRoot, 'scripts'), { recursive: true })
  writeFileSync(join(repoRoot, 'ios', 'Sources', 'App.swift'), 'product\n')
  writeFileSync(join(repoRoot, 'scripts', 'ios-build'), 'controller v1\n')
  git('add', '.')
  git('commit', '-qm', 'product')
  const receiptCommit = git('rev-parse', 'HEAD')
  const receiptTree = git('rev-parse', 'HEAD^{tree}')
  writeFileSync(join(repoRoot, 'scripts', 'ios-build'), 'controller v2\n')
  git('add', '.')
  git('commit', '-qm', 'harness')
  const candidateCommit = git('rev-parse', 'HEAD')
  const candidateTree = git('rev-parse', 'HEAD^{tree}')
  const sourceEquivalence = proveUnchangedPlatformInputs({
    candidateRoot: repoRoot,
    platform: 'ios',
    receiptCommit,
    receiptTree,
    candidateCommit,
    candidateTree,
  })
  writeFileSync(join(repoRoot, 'ios', 'Sources', 'App.swift'), 'changed product\n')
  git('add', '.')
  git('commit', '-qm', 'product change')
  assert.throws(
    () => proveUnchangedPlatformInputs({
      candidateRoot: repoRoot,
      platform: 'ios',
      receiptCommit,
      receiptTree,
      candidateCommit: git('rev-parse', 'HEAD'),
      candidateTree: git('rev-parse', 'HEAD^{tree}'),
    }),
    /changed product\/build input ios\/Sources\/App\.swift/i,
  )

  const exportDir = join(repoRoot, 'dist', 'ios', 'export')
  const frozenDir = join(repoRoot, 'dist', 'ios', 'frozen')
  mkdirSync(exportDir, { recursive: true })
  mkdirSync(frozenDir, { recursive: true })
  const ipaPath = join(exportDir, 'NostrVpnIos.ipa')
  const receiptPath = join(frozenDir, 'app-store-receipt.json')
  writeFileSync(ipaPath, 'retained product ipa')
  const ipaSha256 = createHash('sha256').update(readFileSync(ipaPath)).digest('hex')
  const signer = '3'.repeat(64)
  const receipt = {
    receiptSchema: 1,
    artifactType: 'iOS export from frozen xcarchive',
    distribution: 'app-store-connect',
    appGitSha: receiptCommit,
    appGitTree: receiptTree,
    ipaSha256,
    identity: {
      appBundleIdentifier: 'fi.siriusbusiness.nvpn',
      appBuildGitSha: receiptCommit,
      buildNumber: '4001008',
      marketingVersion: '4.1.5',
      packetTunnelBuildGitSha: receiptCommit,
    },
    signing: {
      signerCertificateSha256: signer,
      signingTeamIdentifier: 'ABCDEFGHIJ',
    },
  }
  writeFileSync(receiptPath, `${JSON.stringify(receipt)}\n`)
  const stagedManifest = {
    tag: 'v4.1.5',
    commit: candidateCommit,
    release_gate_attestation: { app_git_tree: candidateTree },
    ios_app_store_gate: {
      receipt_schema: 1,
      app_git_sha: receiptCommit,
      app_git_tree: receiptTree,
      bundle_id: 'fi.siriusbusiness.nvpn',
      marketing_version: '4.1.5',
      build_number: '4001008',
      ipa_sha256: ipaSha256,
      ipa_size: statSync(ipaPath).size,
      export_receipt_sha256: createHash('sha256')
        .update(readFileSync(receiptPath)).digest('hex'),
      signing_team_id: 'ABCDEFGHIJ',
      signer_certificate_sha256: signer,
      source_equivalence: sourceEquivalence,
    },
  }
  assert.equal(
    validateFrozenIosPublication({ repoRoot, stagedManifest }).ipaPath,
    ipaPath,
  )
  stagedManifest.ios_app_store_gate.source_equivalence = {
    ...sourceEquivalence,
    changed_paths_sha256: '0'.repeat(64),
  }
  assert.throws(
    () => validateFrozenIosPublication({ repoRoot, stagedManifest }),
    /source proof|differs from exact staging/i,
  )
})

test('retained iOS export runs only from its proven artifact source', () => {
  const source = readFileSync(
    new URL('./local-release.mjs', import.meta.url),
    'utf8',
  )
  for (const required of [
    'requireReceiptSource(archiveReceipt',
    "'worktree', 'add', '--detach', sourceRoot, archiveReceipt.appGitSha",
    "for (const name of ['dist', 'artifacts'])",
    'mkdirSync(linkRoot)',
    'for (const entry of readdirSync(externalRoot))',
    'join(linkRoot, entry)',
    "join(repoRoot, 'scripts', 'ios-build'), 'ios-export'",
    'NVPN_BUILD_GIT_SHA: archiveReceipt.appGitSha',
    'NVPN_IOS_RELEASE_SOURCE_ROOT: sourceRoot',
    'source_equivalence: sourceEquivalence',
  ]) {
    assert.match(source, new RegExp(required.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')))
  }
  assert.doesNotMatch(
    source,
    /join\(sourceRoot, 'scripts', 'ios-build'\), 'ios-export'/,
  )
})

test('retained iOS outputs stay available without dirtying the exact checkout', (context) => {
  const root = mkdtempSync(join(tmpdir(), 'nvpn-ios-export-links-'))
  context.after(() => rmSync(root, { recursive: true, force: true }))
  const checkout = join(root, 'source')
  const external = join(root, 'external')
  mkdirSync(checkout)
  mkdirSync(join(external, 'dist', 'ios'), { recursive: true })
  writeFileSync(join(external, 'dist', 'ios', 'archive'), 'exact bytes\n')
  writeFileSync(join(checkout, '.gitignore'), 'dist/\nartifacts/\n')
  const git = (...args) => spawnSync('git', args, {
    cwd: checkout,
    encoding: 'utf8',
  })
  assert.equal(git('init', '--quiet').status, 0)
  assert.equal(git('add', '.gitignore').status, 0)
  assert.equal(git(
    '-c', 'user.name=release-test',
    '-c', 'user.email=release-test@invalid',
    'commit', '--quiet', '-m', 'fixture',
  ).status, 0)

  symlinkSync(join(external, 'dist'), join(checkout, 'dist'), 'dir')
  assert.match(git('status', '--porcelain', '--untracked-files=all').stdout, /\?\? dist/)
  unlinkSync(join(checkout, 'dist'))

  mkdirSync(join(checkout, 'dist'))
  symlinkSync(
    join(external, 'dist', 'ios'),
    join(checkout, 'dist', 'ios'),
    'dir',
  )
  assert.equal(git('status', '--porcelain', '--untracked-files=all').stdout, '')
  assert.equal(
    readFileSync(join(checkout, 'dist', 'ios', 'archive'), 'utf8'),
    'exact bytes\n',
  )
  rmSync(join(checkout, 'dist'), { recursive: true, force: true })
  assert.equal(statSync(join(external, 'dist', 'ios', 'archive')).size, 12)
})


test('accepted pending iOS upload waits or finalizes without duplicate upload', () => {
  const intent = { path: '/private/intent', value: {} }
  const pending = { path: '/private/pending', value: {} }
  assert.equal(
    planIosUploadReconciliation({
      buildPresent: false,
      finalReceipt: null,
      intentReceipt: intent,
      pendingReceipt: pending,
    }),
    'wait-pending',
  )
  assert.equal(
    planIosUploadReconciliation({
      buildPresent: true,
      finalReceipt: null,
      intentReceipt: intent,
      pendingReceipt: pending,
    }),
    'finalize-pending',
  )
  assert.throws(
    () =>
      planIosUploadReconciliation({
        buildPresent: true,
        finalReceipt: null,
        intentReceipt: null,
        pendingReceipt: null,
      }),
    /orphan app store connect build/i,
  )
  assert.equal(
    planIosUploadReconciliation({
      buildPresent: true,
      finalReceipt: '/private/final',
      intentReceipt: intent,
      pendingReceipt: pending,
    }),
    'use-final',
  )
  assert.throws(
    () =>
      planIosUploadReconciliation({
        buildPresent: true,
        finalReceipt: '/private/final',
        intentReceipt: intent,
        pendingReceipt: null,
      }),
    /without every predecessor/i,
  )

  const publisher = readFileSync(
    join(process.cwd(), 'scripts/ios-release-publication.mjs'),
    'utf8',
  )
  const intentWrite = publisher.indexOf('writeIosUploadIntent({')
  const upload = publisher.indexOf("'ios-upload'", intentWrite)
  const pendingWrite = publisher.indexOf(
    'writeAcceptedIosPendingUpload({',
    upload,
  )
  assert.ok(intentWrite >= 0 && upload > intentWrite && pendingWrite > upload)
  assert.match(
    publisher,
    /if \(intent\.created\) \{[\s\S]*?ios-upload[\s\S]*?writeAcceptedIosPendingUpload/,
  )
  assert.match(
    publisher,
    /captureIosUploadIntent\(\{[\s\S]*?beforeMutation\(\)\s*const intent = writeIosUploadIntent\(/,
  )
  assert.match(
    publisher,
    /receipts\.uploadAction === 'wait-intent'[\s\S]*?receipts\.uploadAction === 'wait-pending'[\s\S]*?testflight-internal'\), 'wait'/,
  )
  assert.match(
    publisher,
    /for \(const \[script, action\] of \[[\s\S]*?'put'[\s\S]*?'public'[\s\S]*?\]\) \{[\s\S]*?validateIosUploadReceipt\([\s\S]*?beforeMutation\(\)\s*run\(/,
  )
  assert.match(
    publisher,
    /!submittedStates\.has[\s\S]*?\) \{\s*beforeMutation\(\)\s*run\([\s\S]*?'appstore-draft'\), 'submit'/,
  )
  assert.doesNotMatch(publisher, /removeIosPendingUploadReceipt|unlinkSync/)
})

test('local release CLI and environment enforce required Zapstore mode', () => {
  const script = join(process.cwd(), 'scripts/local-release.mjs')
  const cliConflict = spawnSync(
    process.execPath,
    [script, '--dry-run', '--require-zapstore', '--skip-zapstore'],
    { encoding: 'utf8' },
  )
  assert.equal(cliConflict.status, 1)
  assert.match(cliConflict.stderr, /require-zapstore conflicts with --skip-zapstore/)

  const envConflict = spawnSync(
    process.execPath,
    [script, '--dry-run', '--skip-zapstore'],
    {
      encoding: 'utf8',
      env: { ...process.env, NVPN_RELEASE_REQUIRE_ZAPSTORE: 'true' },
    },
  )
  assert.equal(envConflict.status, 1)
  assert.match(envConflict.stderr, /require-zapstore conflicts with --skip-zapstore/)

  const nonFinal = spawnSync(
    process.execPath,
    [script, '--require-zapstore'],
    { encoding: 'utf8' },
  )
  assert.equal(nonFinal.status, 1)
  assert.match(nonFinal.stderr, /needs --final or --promote-draft/)
})

test('staged draft publication rejects build, final, and distribution flags', () => {
  const script = join(process.cwd(), 'scripts/local-release.mjs')
  const conflicts = [
    ['--publish'],
    ['--draft'],
    ['--final'],
    ['--promote-draft'],
    ['--cargo-publish'],
    ['--skip-cargo-publish'],
    ['--skip-zapstore'],
    ['--skip-umbrel'],
    ['--require-zapstore'],
    ['--skip-verify'],
    ['--only', 'verify'],
    ['--skip', 'ios'],
    ['--allow-partial'],
  ]

  for (const conflict of conflicts) {
    const result = spawnSync(
      process.execPath,
      [script, '--publish-staged-draft', '--dry-run', ...conflict],
      { encoding: 'utf8' },
    )
    assert.equal(result.status, 1, conflict.join(' '))
    assert.match(
      result.stderr,
      /--publish-staged-draft cannot be combined with/i,
      conflict.join(' '),
    )
  }
})

test('draft promotion makes verified multi-arch Umbrel publication a default release channel', () => {
  const localRelease = readFileSync(join(process.cwd(), 'scripts/local-release.mjs'), 'utf8')
  const promoteStart = localRelease.indexOf('if (options.promoteDraft)')
  const promoteEnd = localRelease.indexOf('\n  const steps = [', promoteStart)
  const promote = localRelease.slice(promoteStart, promoteEnd)

  assert.match(localRelease, /--skip-umbrel/)
  assert.match(localRelease, /NVPN_UMBREL_IMAGE_REPO/)
  assert.ok(promote.indexOf('preflightUmbrelPublication({') >= 0)
  assert.ok(
    promote.indexOf('preflightUmbrelPublication({')
      < promote.indexOf('publishExactIosDistribution({'),
  )
  assert.match(
    promote,
    /publishVerifiedUmbrelRelease\(\{[\s\S]*?beforeMutation:\s*\(\)\s*=>\s*replayCanonicalMutationGate\(\{[\s\S]*?requireTag:\s*true/,
  )
  assert.match(promote, /platforms:\s*\['linux\/amd64',\s*'linux\/arm64'\]/)
})

test('direct htree and crates publication paths fail closed', () => {
  const script = join(process.cwd(), 'scripts/local-release.mjs')
  for (const [args, message] of [
    [['--publish', '--dry-run'], /Direct --publish\/--final is disabled/],
    [['--final', '--dry-run'], /Direct --publish\/--final is disabled/],
    [['--cargo-publish', '--dry-run'], /Direct --cargo-publish is disabled/],
  ]) {
    const result = spawnSync(process.execPath, [script, ...args], {
      encoding: 'utf8',
    })
    assert.equal(result.status, 1, args.join(' '))
    assert.match(result.stderr, message, args.join(' '))
  }
})


test('canonical mutation gate rejects a symlinked stage directory', () => {
  const root = mkdtempSync(join(tmpdir(), 'nvpn-stage-symlink-test-'))
  const exact = join(root, 'exact')
  const substituted = join(root, 'stage')
  mkdirSync(exact)
  symlinkSync(exact, substituted)

  assert.throws(
    () => assertRealStageDirectory(substituted),
    /non-symlink directory/i,
  )
  assert.doesNotThrow(() => assertRealStageDirectory(exact))
})

test('every publisher runs only after exact staged-source validation', () => {
  const source = readFileSync(
    join(process.cwd(), 'scripts/local-release.mjs'),
    'utf8',
  )
  const stagedStart = source.indexOf(
    'if (options.publishStagedDraft) {\n    const stagedManifest',
  )
  const stagedEnd = source.indexOf(
    '\n  if (\n    options.publish',
    stagedStart,
  )
  const staged = source.slice(stagedStart, stagedEnd)
  assert.ok(stagedStart >= 0 && stagedEnd > stagedStart)
  assert.ok(
    staged.indexOf('preflightHtreeRelease({')
    < staged.indexOf('publishRelease({'),
  )
  assert.match(
    staged,
    /beforeMutation:\s*\(\)\s*=>\s*\{[\s\S]*?preflightHtreeRelease\(\{[\s\S]*?replayCanonicalMutationGate\(\{[\s\S]*?requireTag:\s*false/,
  )

  const promoteStart = source.indexOf(
    'if (options.promoteDraft) {\n    if (!commandExists',
  )
  const promoteEnd = source.indexOf('\n  const steps = [', promoteStart)
  const promote = source.slice(promoteStart, promoteEnd)
  assert.ok(promoteStart >= 0 && promoteEnd > promoteStart)
  assert.match(
    promote,
    /promoteStagedDraft\(\{[\s\S]*?beforeMutation:\s*\(\)\s*=>\s*\{[\s\S]*?preflightHtreeRelease\(\{[\s\S]*?replayCanonicalMutationGate\(\{[\s\S]*?requireTag:\s*true/,
  )
  assert.match(
    promote,
    /Promoted \$\{tag\}[\s\S]*?replayCanonicalMutationGate\(\{[\s\S]*?requireTag:\s*true[\s\S]*?publishExactGithubRelease\(\{/,
  )
})

test('GitHub mutation uses the repository pinned by preflight', () => {
  const source = readFileSync(
    join(process.cwd(), 'scripts/github-release-publication.mjs'),
    'utf8',
  )
  assert.match(
    source,
    /const repository = exactGithubRepository\(\{ repoRoot \}\)/,
  )
  assert.match(
    source,
    /expected:\s*repository/,
  )
  assert.doesNotMatch(source, /arguments_\s*\[/)
  assert.match(
    source,
    /beforeMutation\(\)[\s\S]*?const mutationRepository = exactGithubRepository\(\{[\s\S]*?const arguments_ = \[[\s\S]*?'create'[\s\S]*?'--repo',[\s\S]*?mutationRepository/,
  )
  for (const command of ['upload', 'edit']) {
    assert.match(
      source,
      new RegExp(
        `beforeMutation\\(\\)[\\s\\S]*?const mutationRepository = exactGithubRepository\\(\\{[\\s\\S]*?'${command}',[\\s\\S]*?'--repo',[\\s\\S]*?mutationRepository`,
      ),
      command,
    )
  }
  for (const command of ['view', 'download', 'upload', 'edit', 'create']) {
    assert.match(
      source,
      new RegExp(`'${command}',[\\s\\S]{0,180}?'--repo'`),
      command,
    )
  }
})

test('staged draft publication publishes only the already validated bytes', () => {
  const root = mkdtempSync(join(tmpdir(), 'nostr-vpn-staged-draft-test-'))
  const repo = join(root, 'repo')
  const scripts = join(repo, 'scripts')
  const stage = join(root, 'stage')
  const assetsDir = join(stage, 'assets')
  const bin = join(root, 'bin')
  const htreeLog = join(root, 'htree.log')
  mkdirSync(scripts, { recursive: true })
  mkdirSync(assetsDir, { recursive: true })
  mkdirSync(bin, { recursive: true })

  for (const args of [
    ['init', '-q'],
    ['config', 'user.email', 'release-test@example.invalid'],
    ['config', 'user.name', 'Release Test'],
    ['remote', 'add', 'origin', 'htree://self/test'],
  ]) {
    const result = spawnSync('git', args, { cwd: repo, encoding: 'utf8' })
    assert.equal(result.status, 0, result.stderr)
  }
  writeFileSync(join(repo, 'README.md'), 'base revision for stale-tag test\n')
  for (const args of [
    ['add', '.'],
    ['commit', '-qm', 'base source'],
  ]) {
    const result = spawnSync('git', args, { cwd: repo, encoding: 'utf8' })
    assert.equal(result.status, 0, result.stderr)
  }

  for (const name of [
    'local-release.mjs',
    'local-release-lib.mjs',
    'release-source-verification.mjs',
    'release-artifact-provenance-lib.mjs',
    'release-gate-resume.mjs',
    'release-component-source.mjs',
    'github-release-publication.mjs',
    'htree-release-publication.mjs',
    'ios-release-publication.mjs',
    'ios-upload-receipt.mjs',
    'release-mutation-gate.mjs',
    'verify-release-publication-bundle.mjs',
    'startos-release.mjs',
    'umbrel-release.mjs',
    'zapstore-release-publication.mjs',
  ]) {
    copyFileSync(join(process.cwd(), 'scripts', name), join(scripts, name))
  }
  mkdirSync(join(repo, 'startos', 'versions'), { recursive: true })
  writeFileSync(
    join(repo, 'startos', 'versions', 'current.ts'),
    "version: '4.1.5:0'\n",
  )
  writeFileSync(
    join(repo, 'Cargo.toml'),
    '[workspace]\nmembers = []\n\n[workspace.package]\nversion = "4.1.5"\n',
  )
  for (const args of [
    ['add', '.'],
    ['commit', '-qm', 'exact staged source'],
  ]) {
    const result = spawnSync('git', args, { cwd: repo, encoding: 'utf8' })
    assert.equal(result.status, 0, result.stderr)
  }
  const commit = spawnSync('git', ['rev-parse', 'HEAD'], {
    cwd: repo,
    encoding: 'utf8',
  }).stdout.trim()
  const tree = spawnSync('git', ['rev-parse', 'HEAD^{tree}'], {
    cwd: repo,
    encoding: 'utf8',
  }).stdout.trim()

  const assetNames = [
    'nostr-vpn-v4.1.5-android-arm64.apk',
    'nostr-vpn-v4.1.5-linux-x64.deb',
    'nvpn-v4.1.5-x86_64-unknown-linux-musl.tar.gz',
    'nvpn-v4.1.5-aarch64-unknown-linux-musl.tar.gz',
    'nostr-vpn-v4.1.5-macos-arm64.app.tar.gz',
    'nostr-vpn-v4.1.5-macos-arm64.dmg',
    'nostr-vpn-v4.1.5-startos-aarch64.s9pk',
    'nostr-vpn-v4.1.5-startos-x86_64.s9pk',
    'nostr-vpn-v4.1.5-windows-x64-setup.exe',
  ]
  const assetPaths = assetNames.map((name) => {
    const path = join(assetsDir, name)
    writeFileSync(path, `exact pre-staged bytes for ${name}\n`)
    return path
  })
  const androidPath = assetPaths[0]
  const androidSha256 = createHash('sha256')
    .update(readFileSync(androidPath))
    .digest('hex')
  const manifest = buildReleaseManifest({
    tag: 'v4.1.5',
    commit,
    createdAt: 123,
    assetPaths,
    draft: true,
    androidReleaseGate: {
      receipt_schema: 2,
      apk_path: `assets/${assetNames[0]}`,
      apk_sha256: androidSha256,
      app_git_sha: commit,
      app_git_tree: tree,
      package: 'fi.siriusbusiness.nvpn',
      signer_certificate_sha256: 'e'.repeat(64),
    },
  })
  const receiptDigests = Object.fromEntries(
    ['android', 'ios', 'linux', 'macos', 'windows'].map(
      (platform, index) => [
        platform,
        { gate: String(index + 1).padStart(64, '0') },
      ],
    ),
  )
  const summarySha256 = '9'.repeat(64)
  const platformForAsset = (path) => {
    for (const platform of ['android', 'linux', 'macos', 'windows']) {
      if (path.includes(platform)) return platform
    }
    return 'startos'
  }
  const assetProofs = Object.fromEntries(
    manifest.assets.map((asset) => {
      const platform = platformForAsset(asset.path)
      return [
        asset.path,
        {
          platform,
          verification:
            platform === 'startos'
              ? 'post-build-exact-package-gate'
              : 'gate-payload-identity',
          artifact_sha256: asset.sha256,
          gate_receipt_sha256:
            platform === 'startos'
              ? summarySha256
              : receiptDigests[platform].gate,
          ...(platform === 'startos'
            ? { post_build_validator: startosExactPackageValidator }
            : {}),
          payloads:
            platform === 'startos'
              ? {
                  manifest_json: createHash('sha256')
                    .update(
                      `{"id":"nostr-vpn","images":[{"arch":["${
                        asset.name.includes('aarch64')
                          ? 'aarch64'
                          : 'x86_64'
                      }"],"id":"app"}],"version":"4.1.5:0","virtualNetworking":true}`,
                    )
                    .digest('hex'),
                  package: asset.sha256,
                }
              : { runtime: asset.sha256 },
        },
      ]
    }),
  )
  manifest.release_gate_attestation = buildReleaseGateAttestation({
    commit,
    tree,
    assets: manifest.assets,
    releaseGateSummarySha256: summarySha256,
    platformGateReceipts: receiptDigests,
    assetProofs,
  })
  for (const [name, contents] of buildReleaseManifestFiles(manifest)) {
    writeFileSync(join(stage, name), contents)
  }
  writeFileSync(join(stage, 'notes.md'), 'exact staged notes\n')
  const stagedBefore = new Map(
    ['release.json', 'manifest.json', 'notes.md', ...manifest.assets.map(
      (asset) => asset.path,
    )].map((path) => [path, readFileSync(join(stage, path))]),
  )


  const fakeCid = `nhash1${'q'.repeat(58)}`
  const htree = join(bin, 'htree')
  writeFileSync(
    htree,
    `#!/bin/sh
set -eu
printf '%s\\n' "$*" >> "$FAKE_HTREE_LOG"
case "$1" in
  user)
    printf '%s (self)\\n' "$FAKE_HTREE_NPUB"
    ;;
  status)
    ;;
  add)
    printf 'url: %s\\n' "$FAKE_HTREE_CID"
    ;;
  push)
    ;;
  cat)
    relative="\${2#*/}"
    if [ "\${FAKE_HTREE_MUTATE_METADATA:-}" = "$relative" ]; then
      LC_ALL=C /usr/bin/sed '1s/^./X/' "$FAKE_HTREE_STAGE/$relative"
    else
      exec /bin/cat "$FAKE_HTREE_STAGE/$relative"
    fi
    ;;
  release)
    ;;
  *)
    exit 2
    ;;
esac
`,
  )
  chmodSync(htree, 0o755)
  writeFileSync(htreeLog, '')
  const startCli = join(bin, 'start-cli')
  writeFileSync(
    startCli,
    `#!/bin/sh
set -eu
case "$3" in
  *-startos-aarch64.s9pk) arch=aarch64 ;;
  *-startos-x86_64.s9pk) arch=x86_64 ;;
  *) exit 2 ;;
esac
printf '{"id":"nostr-vpn","version":"4.1.5:0","virtualNetworking":true,"images":[{"id":"app","arch":["%s"]}]}\\n' "$arch"
`,
  )
  chmodSync(startCli, 0o755)

  const releaseArgs = [
    join(scripts, 'local-release.mjs'),
    '--publish-staged-draft',
    '--tag',
    'v4.1.5',
    '--stage-dir',
    stage,
    '--release-tree',
    'releases/test',
  ]
  const releaseOptions = {
    cwd: repo,
    encoding: 'utf8',
    env: {
      ...process.env,
      PATH: `${bin}:${process.env.PATH}`,
      FAKE_HTREE_CID: fakeCid,
      FAKE_HTREE_LOG: htreeLog,
      FAKE_HTREE_NPUB: 'npub1xdhnr9mrv47kkrn95k6cwecearydeh8e895990n3acntwvmgk2dsdeeycm',
      FAKE_HTREE_STAGE: stage,
      NVPN_HTREE_PUBLISHER_NPUB:
        'npub1xdhnr9mrv47kkrn95k6cwecearydeh8e895990n3acntwvmgk2dsdeeycm',
    },
  }
  const conflictingResume = spawnSync(
    process.execPath,
    [...releaseArgs, '--complete-gate-from-receipts'],
    releaseOptions,
  )
  assert.equal(conflictingResume.status, 1)
  assert.match(
    conflictingResume.stderr,
    /complete-gate-from-receipts cannot be combined/i,
  )
  assert.equal(readFileSync(htreeLog, 'utf8'), '')

  const unexpectedStagePath = join(stage, 'unsealed.txt')
  writeFileSync(unexpectedStagePath, 'not in the staged manifest\n')
  const unexpectedStageResult = spawnSync(
    process.execPath,
    releaseArgs,
    releaseOptions,
  )
  assert.equal(unexpectedStageResult.status, 1)
  assert.match(
    unexpectedStageResult.stderr,
    /unexpected staged root entries/i,
  )
  assert.equal(readFileSync(htreeLog, 'utf8'), '')
  unlinkSync(unexpectedStagePath)

  const result = spawnSync(
    process.execPath,
    releaseArgs,
    releaseOptions,
  )
  assert.equal(result.status, 0, result.stderr)
  assert.match(result.stdout, /Published staged draft v4\.1\.5/)
  const htreeLogAfterInitialDraft = readFileSync(htreeLog, 'utf8')
  const durableDraftRetry = spawnSync(
    process.execPath,
    releaseArgs,
    releaseOptions,
  )
  assert.equal(durableDraftRetry.status, 0, durableDraftRetry.stderr)
  writeFileSync(htreeLog, htreeLogAfterInitialDraft)

  assert.equal(
    spawnSync('git', ['status', '--porcelain=v1', '--untracked-files=all'], {
      cwd: repo,
      encoding: 'utf8',
    }).stdout,
    '',
  )
  for (const [path, before] of stagedBefore) {
    assert.deepEqual(readFileSync(join(stage, path)), before)
  }

  const htreeCommands = readFileSync(htreeLog, 'utf8').trim().split('\n')
  assert.deepEqual(htreeCommands, [
    'user',
    'status',
    'release publish --help',
    `add ${stage}`,
    'user',
    'status',
    'release publish --help',
    `push --force ${fakeCid}`,
    ...[...stagedBefore.keys()].map((path) => `cat ${fakeCid}/${path}`),
    'user',
    'status',
    'release publish --help',
    `release publish releases/test v4.1.5 ${fakeCid} --draft`,
  ])
  assert.match(
    readFileSync(join(scripts, 'local-release.mjs'), 'utf8'),
    /for \(const path of htreeReleaseMetadataPaths\)[\s\S]*?No exact staged htree metadata binding exists for \$\{path\}/,
  )

  for (const metadataPath of [
    'release.json',
    'manifest.json',
    'notes.md',
  ]) {
    writeFileSync(htreeLog, '')
    const mutatedMetadataResult = spawnSync(
      process.execPath,
      releaseArgs,
      {
        ...releaseOptions,
        env: {
          ...releaseOptions.env,
          FAKE_HTREE_MUTATE_METADATA: metadataPath,
        },
      },
    )
    assert.equal(
      mutatedMetadataResult.status,
      1,
      `${metadataPath}: ${mutatedMetadataResult.stderr}`,
    )
    assert.match(
      mutatedMetadataResult.stderr,
      new RegExp(
        `Published htree CID SHA-256 mismatch for ${metadataPath.replace('.', '\\.')}`,
        'i',
      ),
    )
    assert.doesNotMatch(
      readFileSync(htreeLog, 'utf8'),
      new RegExp(
        `release publish releases/test v4\\.1\\.5 ${fakeCid}`,
      ),
    )
  }
  const staleTag = spawnSync('git', ['tag', 'v4.1.5', 'HEAD^'], {
    cwd: repo,
    encoding: 'utf8',
  })
  assert.equal(staleTag.status, 0, staleTag.stderr)
  const logBeforeStaleTagAttempt = readFileSync(htreeLog, 'utf8')
  const staleTagResult = spawnSync(
    process.execPath,
    releaseArgs,
    releaseOptions,
  )
  assert.equal(staleTagResult.status, 1)
  assert.match(staleTagResult.stderr, /release tag .* not staged commit/i)
  assert.equal(readFileSync(htreeLog, 'utf8'), logBeforeStaleTagAttempt)
})

test('final publication cannot bypass complete platform artifacts', () => {
  const localRelease = readFileSync(join(process.cwd(), 'scripts/local-release.mjs'), 'utf8')

  assert.match(
    localRelease,
    /cliRequired:\s*options\.requireZapstore\s*\|\|\s*finalPublication/,
  )
  assert.match(
    localRelease,
    /final release cannot be published with partial platform artifacts/,
  )
  assert.match(
    localRelease,
    /final release must run every platform step; --only and --skip are staging-only/,
  )
  assert.match(
    localRelease,
    /NVPN_RELEASE_GATE_MOBILE_UNDERLAY_E2E:\s*'1'/,
  )
  assert.match(
    localRelease,
    /real Android\/iOS physical underlay changes/,
  )
})

test('complete staging can reuse only a fully validated gate receipt set', () => {
  const script = join(process.cwd(), 'scripts/local-release.mjs')
  const reused = spawnSync(
    process.execPath,
    [script, '--dry-run', '--only', 'verify', '--reuse-gate-receipts'],
    { encoding: 'utf8' },
  )
  assert.equal(reused.status, 0, reused.stderr)
  assert.doesNotMatch(reused.stdout, /\$ .*release-gate\.sh/)
  assert.match(reused.stdout, /Would stage \d+ currently visible asset/)

  for (const conflict of [
    ['--skip-verify'],
    ['--skip', 'verify'],
    ['--only', 'android'],
    ['--allow-partial'],
    ['--publish-staged-draft'],
    ['--promote-draft'],
  ]) {
    const rejected = spawnSync(
      process.execPath,
      [script, '--dry-run', '--reuse-gate-receipts', ...conflict],
      { encoding: 'utf8' },
    )
    assert.equal(rejected.status, 1, conflict.join(' '))
    assert.match(
      rejected.stderr,
      /requires complete verification.*skipped or partial staging/i,
      conflict.join(' '),
    )
  }

  const source = readFileSync(script, 'utf8')
  const verify = source.slice(
    source.indexOf("['verify', () => {"),
    source.indexOf("['startos'"),
  )
  assert.match(
    verify,
    /if \(options\.reuseGateReceipts\)[\s\S]*?else \{[\s\S]*?runVerify\(/,
  )
  assert.match(verify, /collectReleaseGateReceipts\(\{/)
  assert.doesNotMatch(verify, /releaseGateCompleted/)
})

test('final publication preflights tools and Zapstore identity before the release gate', () => {
  const localRelease = readFileSync(join(process.cwd(), 'scripts/local-release.mjs'), 'utf8')
  const mainStart = localRelease.indexOf('function main()')
  const preflightCall = localRelease.indexOf(
    'preflightExactZapstorePublication({',
    mainStart,
  )
  const buildSteps = localRelease.indexOf('const steps = [', mainStart)

  assert.ok(preflightCall > mainStart)
  assert.ok(preflightCall < buildSteps)
  assert.match(
    localRelease,
    /\(options\.publish\s*\|\|\s*options\.publishStagedDraft\)[\s\S]*?&&\s*!options\.dryRun[\s\S]*?&&\s*!commandExists\('htree'\)/,
  )
  const zapstorePublisher = readFileSync(
    join(process.cwd(), 'scripts/zapstore-release-publication.mjs'),
    'utf8',
  )
  assert.match(
    zapstorePublisher,
    /zapstorePublicationPrerequisites\([\s\S]*?apk:\s*!requireApk\s*\|\|\s*Boolean\(apkPath\s*&&\s*existsSync\(apkPath\)\)/,
  )
  assert.match(zapstorePublisher, /'nak',[\s\S]*\['decode', context\.publisherNpub\]/)
})

test('publication verification requires real Windows and Linux underlay gates', () => {
  const localRelease = readFileSync(join(process.cwd(), 'scripts/local-release.mjs'), 'utf8')
  const verifyStart = localRelease.indexOf('function runVerify(')
  const verifyEnd = localRelease.indexOf('\nfunction buildStartosArtifacts', verifyStart)
  const verify = localRelease.slice(verifyStart, verifyEnd)

  assert.ok(verifyStart >= 0 && verifyEnd > verifyStart)
  assert.match(
    verify,
    /NVPN_RELEASE_GATE_WINDOWS_UNDERLAY_NETWORK_CHANGE_E2E:\s*'1'/,
  )
  assert.match(
    verify,
    /NVPN_RELEASE_GATE_LINUX_UNDERLAY_NETWORK_CHANGE_E2E:\s*'1'/,
  )
  assert.match(verify, /NVPN_RELEASE_GATE_MACOS_WG_EXIT_E2E:\s*'1'/)
  assert.match(verify, /NVPN_RELEASE_GATE_MACOS_GUI_SMOKE:\s*'1'/)
  assert.match(verify, /NVPN_RELEASE_GATE_MACOS_DAEMON_IDLE_CPU:\s*'1'/)
  assert.match(verify, /run\('\.\/scripts\/release-gate\.sh'/)
  assert.match(verify, /real Windows\/Linux desktop underlay changes/)
  assert.match(verify, /isolated macOS VM network\/service proofs/)
})

test('StartOS staging uses an explicit inspected prebuilt directory without builder fallback', () => {
  const source = readFileSync(join(process.cwd(), 'scripts/local-release.mjs'), 'utf8')
  const start = source.indexOf('function buildStartosArtifacts(')
  const end = source.indexOf('\nfunction shouldRunStep(', start)
  const build = source.slice(start, end)

  assert.match(build, /NVPN_RELEASE_STARTOS_ARTIFACT_DIR/)
  assert.match(build, /if \(!prebuiltArtifactDir\)[\s\S]*?startos-release\.mjs/)
  assert.match(build, /prebuiltPackages = \['x86_64', 'aarch64'\]\.map/)
  assert.match(build, /if \(prebuilt\) copyFileSync/)
})

test('release builds include paid exit support by default', () => {
  for (const manifest of [
    'crates/nostr-vpn-core/Cargo.toml',
    'crates/nostr-vpn-cli/Cargo.toml',
    'crates/nostr-vpn-app-core/Cargo.toml',
  ]) {
    const contents = readFileSync(manifest, 'utf8')
    assert.match(contents, /default\s*=\s*\[[^\]]*"paid-exit"[^\]]*\]/)
  }

  const linuxBuilder = readFileSync('scripts/build-nvpn-linux-musl', 'utf8')
  const releaseWorkflow = readFileSync('.github/workflows/release.yml', 'utf8')
  assert.match(
    linuxBuilder,
    /if \[\[ \$\{NVPN_LINUX_MUSL_NO_DEFAULT_FEATURES:-0\} == 1 \]\]; then[\s\S]*cargo_feature_args\+=\(--no-default-features\)/,
  )
  assert.doesNotMatch(releaseWorkflow, /NVPN_LINUX_MUSL_NO_DEFAULT_FEATURES/)
})

test('Linux musl builds extract only rustables instead of vendoring every dependency', () => {
  const linuxBuilder = readFileSync('scripts/build-nvpn-linux-musl', 'utf8')

  assert.doesNotMatch(linuxBuilder, /\bcargo\b[^\n]*\bvendor\b/)
  assert.match(linuxBuilder, /rustables-\$\{rustables_version\}\.crate/)
  assert.match(linuxBuilder, /tar -xzf "\$rustables_crate" -C vendor/)
})

test('deterministicBuildEnv fills stable defaults without clobbering explicit env', () => {
  assert.deepEqual(
    deterministicBuildEnv(
      { CARGO_INCREMENTAL: '1', TZ: 'Europe/Helsinki' },
      { sourceDateEpoch: 123 },
    ),
    {
      SOURCE_DATE_EPOCH: '123',
      CARGO_INCREMENTAL: '1',
      ZERO_AR_DATE: '1',
      LC_ALL: 'C',
      TZ: 'Europe/Helsinki',
    },
  )
})

test('deterministicBuildEnv rejects non-numeric source dates', () => {
  assert.throws(
    () => deterministicBuildEnv({}, { sourceDateEpoch: 'today' }),
    /SOURCE_DATE_EPOCH/,
  )
})

test('Windows release transport supports jump hosts and proxy commands', () => {
  assert.deepEqual(windowsSshTransportArgs({ NVPN_WINDOWS_SSH_JUMP: 'jump-host' }), [
    '-o',
    'BatchMode=yes',
    '-o',
    'ConnectTimeout=10',
    '-J',
    'jump-host',
  ])
  assert.deepEqual(
    windowsSshTransportArgs({
      NVPN_WINDOWS_SSH_JUMP: 'ignored',
      NVPN_WINDOWS_SSH_PROXY_COMMAND: 'ssh gateway -W %h:%p',
    }),
    [
      '-o',
      'BatchMode=yes',
      '-o',
      'ConnectTimeout=10',
      '-o',
      'ProxyCommand=ssh gateway -W %h:%p',
    ],
  )
})

test('Windows publication does not depend on a retained remote VM workspace', () => {
  const source = readFileSync('scripts/local-release.mjs', 'utf8')
  const start = source.indexOf('function buildWindowsArtifacts(')
  const end = source.indexOf('\nfunction buildLinuxArtifacts(', start)
  const build = source.slice(start, end)

  assert.match(build, /NVPN_WINDOWS_RELEASE_ARCHIVE_PATH/)
  assert.match(build, /exactRegularFile\(retainedArchivePath/)
  assert.doesNotMatch(build, /runWindowsPowerShell|pushFileToWindowsHost|pullFileFromWindowsHost/)
  assert.doesNotMatch(source, /function runWindowsPowerShell\(/)
})

test('readWorkspaceVersionTag reads the workspace package version', () => {
  const tag = readWorkspaceVersionTag(`
[workspace]
members = []

[workspace.package]
version = "0.2.27"
`)

  assert.equal(tag, 'v0.2.27')
})

test('buildReleaseManifest can mark htree draft releases', () => {
  const root = mkdtempSync(join(tmpdir(), 'nostr-vpn-manifest-draft-test-'))
  const asset = join(root, 'asset.tar.gz')
  writeFileSync(asset, 'asset')

  const manifest = buildReleaseManifest({
    tag: 'v1.2.3',
    commit: 'abc123',
    createdAt: 123,
    assetPaths: [asset],
    draft: true,
  })

  assert.equal(manifest.draft, true)
  assert.equal(manifest.prerelease, false)
})

test('linuxReleaseTargetsForDockerPlatform maps Docker platforms to release targets', () => {
  assert.deepEqual(linuxReleaseTargetsForDockerPlatform('linux/arm64'), {
    linuxArchSuffix: 'arm64',
    muslTriple: 'aarch64-unknown-linux-musl',
  })
  assert.deepEqual(linuxReleaseTargetsForDockerPlatform('linux/arm64/v8'), {
    linuxArchSuffix: 'arm64',
    muslTriple: 'aarch64-unknown-linux-musl',
  })
  assert.deepEqual(linuxReleaseTargetsForDockerPlatform('linux/amd64'), {
    linuxArchSuffix: 'x64',
    muslTriple: 'x86_64-unknown-linux-musl',
  })
  assert.throws(
    () => linuxReleaseTargetsForDockerPlatform('linux/arm/v7'),
    /Unsupported Linux Docker architecture/,
  )
})

test('shouldBlockLocalLinuxAmd64Qemu protects Apple Silicon Docker Desktop releases', () => {
  assert.equal(
    shouldBlockLocalLinuxAmd64Qemu({
      platform: 'linux/amd64',
      hostPlatform: 'darwin',
      hostArch: 'arm64',
    }),
    true,
  )
  assert.equal(
    shouldBlockLocalLinuxAmd64Qemu({
      platform: 'linux/amd64',
      hostPlatform: 'linux',
      hostArch: 'x64',
    }),
    false,
  )
  assert.equal(
    shouldBlockLocalLinuxAmd64Qemu({
      platform: 'linux/arm64',
      hostPlatform: 'darwin',
      hostArch: 'arm64',
    }),
    false,
  )
})

test('validateReleaseAssetSet rejects ARM64-only Linux desktop releases', () => {
  assert.throws(
    () =>
      validateReleaseAssetSet([
        'nostr-vpn-v0.3.23-linux-arm64.AppImage',
        'nostr-vpn-v0.3.23-linux-arm64.deb',
      ]),
    /no Linux x64 desktop artifacts/,
  )
  assert.doesNotThrow(() =>
    validateReleaseAssetSet([
      'nostr-vpn-v0.3.23-linux-x64.AppImage',
      'nostr-vpn-v0.3.23-linux-arm64.AppImage',
    ]),
  )
  assert.doesNotThrow(() =>
    validateReleaseAssetSet(['nostr-vpn-v0.3.23-linux-arm64.AppImage'], {
      allowLinuxArm64DesktopOnly: true,
    }),
  )
})

test('validateReleaseAssetSet rejects macOS app zip releases', () => {
  assert.throws(
    () => validateReleaseAssetSet(['nostr-vpn-v4.0.1-macos-arm64.zip']),
    /macOS \.zip app archive/,
  )
  assert.throws(
    () => validateReleaseAssetSet(['nostr-vpn-v4.0.1-macos-arm64.dmg']),
    /no macOS \.app\.tar\.gz updater archive/,
  )
  assert.doesNotThrow(() =>
    validateReleaseAssetSet([
      'nostr-vpn-v4.0.1-macos-arm64.app.tar.gz',
      'nostr-vpn-v4.0.1-macos-arm64.dmg',
    ]),
  )
})

test('validateReleaseAssetSet rejects unsigned Android artifacts', () => {
  assert.throws(
    () => validateReleaseAssetSet(['nostr-vpn-v4.0.1-android-arm64-unsigned.apk']),
    /unsigned Android artifacts/,
  )
})

test('validateReleaseAssetSet can require complete app release artifacts', () => {
  assert.throws(
    () =>
      validateReleaseAssetSet([
        'nostr-vpn-v4.0.1-macos-arm64.app.tar.gz',
        'nostr-vpn-v4.0.1-macos-arm64.dmg',
      ], { requireCompleteAppRelease: true }),
    /Linux x64 desktop package, Linux x64 CLI, Linux ARM64 CLI, Windows x64 installer/,
  )

  assert.doesNotThrow(() =>
    validateReleaseAssetSet([
      'nostr-vpn-v4.0.1-android-arm64.aab',
      'nostr-vpn-v4.0.1-android-arm64.apk',
      'nostr-vpn-v4.0.1-linux-x64.deb',
      'nvpn-v4.0.1-x86_64-unknown-linux-musl.tar.gz',
      'nvpn-v4.0.1-aarch64-unknown-linux-musl.tar.gz',
      'nostr-vpn-v4.0.1-macos-arm64.app.tar.gz',
      'nostr-vpn-v4.0.1-macos-arm64.dmg',
      'nostr-vpn-v4.0.1-startos-aarch64.s9pk',
      'nostr-vpn-v4.0.1-startos-x86_64.s9pk',
      'nostr-vpn-v4.0.1-windows-x64-setup.exe',
    ], { requireCompleteAppRelease: true }),
  )
  assert.throws(
    () => validateReleaseAssetSet(['nvpn-arm-unknown-linux-musleabihf.tar.gz']),
    /private-fleet ARMv6/,
  )
})

test('draft promotion rejects an incomplete cross-platform artifact set', () => {
  const commit = 'a'.repeat(40)
  const apkSha256 = 'b'.repeat(64)
  const androidGate = {
    receipt_schema: 2,
    apk_path: 'assets/nostr-vpn-v4.1.4-android-arm64.apk',
    apk_sha256: apkSha256,
    app_git_sha: commit,
    app_git_tree: 'd'.repeat(40),
    package: 'fi.siriusbusiness.nvpn',
    signer_certificate_sha256: 'e'.repeat(64),
  }
  assert.throws(
    () =>
      validatePromotableReleaseManifest({
        assets: [
          { path: 'assets/nostr-vpn-v4.1.4-macos-arm64.app.tar.gz' },
          { path: 'assets/nostr-vpn-v4.1.4-macos-arm64.dmg' },
        ],
      }),
    /Linux x64 desktop package, Linux x64 CLI, Linux ARM64 CLI, Windows x64 installer/,
  )

  const completeAssets = [
    {
      path: 'assets/nostr-vpn-v4.1.4-android-arm64.apk',
      sha256: apkSha256,
      size: 1,
    },
    { path: 'assets/nostr-vpn-v4.1.4-linux-x64.deb', size: 1 },
    { path: 'assets/nvpn-v4.1.4-x86_64-unknown-linux-musl.tar.gz', size: 1 },
    { path: 'assets/nvpn-v4.1.4-aarch64-unknown-linux-musl.tar.gz', size: 1 },
    { path: 'assets/nostr-vpn-v4.1.4-macos-arm64.app.tar.gz', size: 1 },
    { path: 'assets/nostr-vpn-v4.1.4-macos-arm64.dmg', size: 1 },
    { path: 'assets/nostr-vpn-v4.1.4-startos-aarch64.s9pk', size: 1 },
    { path: 'assets/nostr-vpn-v4.1.4-startos-x86_64.s9pk', size: 1 },
    { path: 'assets/nostr-vpn-v4.1.4-windows-x64-setup.exe', size: 1 },
  ].map((asset, index) => ({
    sha256: String(index + 1).padStart(64, '0'),
    ...asset,
  }))
  const platformGateReceipts = Object.fromEntries(
    ['android', 'ios', 'linux', 'macos', 'windows'].map(
      (platform, index) => [
        platform,
        { receipt: String(index + 20).padStart(64, '0') },
      ],
    ),
  )
  const platformForAsset = (path) => {
    if (path.includes('android')) return 'android'
    if (path.includes('linux')) return 'linux'
    if (path.includes('macos')) return 'macos'
    if (path.includes('windows')) return 'windows'
    return 'startos'
  }
  const assetProofs = Object.fromEntries(
    completeAssets.map((asset) => {
      const platform = platformForAsset(asset.path)
      return [
        asset.path,
        {
          platform,
          verification:
            platform === 'startos'
              ? 'post-build-exact-package-gate'
              : 'gate-payload-identity',
          artifact_sha256: asset.sha256,
          gate_receipt_sha256:
            platform === 'startos'
              ? '9'.repeat(64)
              : platformGateReceipts[platform].receipt,
          ...(platform === 'startos'
            ? { post_build_validator: startosExactPackageValidator }
            : {}),
          payloads:
            platform === 'startos'
              ? {
                  manifest_json: '8'.repeat(64),
                  package: asset.sha256,
                }
              : { runtime: asset.sha256 },
        },
      ]
    }),
  )
  const releaseGateAttestation = buildReleaseGateAttestation({
    commit,
    tree: 'd'.repeat(40),
    assets: completeAssets,
    releaseGateSummarySha256: '9'.repeat(64),
    platformGateReceipts,
    assetProofs,
  })
  assert.throws(
    () =>
      validatePromotableReleaseManifest({
        commit,
        assets: completeAssets,
      }),
    /physical Android gate provenance/,
  )
  assert.doesNotThrow(() =>
    validatePromotableReleaseManifest({
      commit,
      assets: completeAssets,
      android_release_gate: androidGate,
      release_gate_attestation: releaseGateAttestation,
    }),
  )
  assert.throws(
    () => validatePromotableReleaseManifest({
      commit,
      assets: completeAssets,
      android_release_gate: {
        ...androidGate,
        app_git_sha: '1'.repeat(40),
        app_git_tree: '2'.repeat(40),
      },
      release_gate_attestation: releaseGateAttestation,
    }),
    /Android gate.*release candidate/i,
  )
  assert.throws(
    () =>
      validatePromotableReleaseManifest({
        commit,
        assets: completeAssets,
        android_release_gate: {
          ...androidGate,
          apk_sha256: 'f'.repeat(64),
        },
        release_gate_attestation: releaseGateAttestation,
      }),
    /physical Android gate.*APK/i,
  )
})

test('release-gate attestation seals every staged asset and all real platforms', () => {
  const commit = 'a'.repeat(40)
  const tree = 'b'.repeat(40)
  const assets = [
    {
      path: 'assets/nostr-vpn-v4.1.5-linux-x64.deb',
      sha256: 'c'.repeat(64),
      size: 42,
    },
  ]
  const receipts = Object.fromEntries(
    ['android', 'ios', 'linux', 'macos', 'windows'].map(
      (platform, index) => [
        platform,
        { gate: String(index + 1).padStart(64, '0') },
      ],
    ),
  )
  const attestation = buildReleaseGateAttestation({
    commit,
    tree,
    assets,
    releaseGateSummarySha256: 'd'.repeat(64),
    platformGateReceipts: receipts,
    assetProofs: {
      [assets[0].path]: {
        platform: 'linux',
        verification: 'gate-payload-identity',
        artifact_sha256: assets[0].sha256,
        gate_receipt_sha256: receipts.linux.gate,
        payloads: { runtime: assets[0].sha256 },
      },
    },
  })
  const manifest = {
    commit,
    assets,
    release_gate_attestation: attestation,
  }
  assert.equal(attestation.asset_set_sha256, releaseAssetSetSha256(assets))
  assert.doesNotThrow(() => validateReleaseGateAttestation(manifest))

  assert.throws(
    () =>
      validateReleaseGateAttestation({
        ...manifest,
        assets: [{ ...assets[0], sha256: 'e'.repeat(64) }],
      }),
    /differs from its exact-artifact proof|assets differ from the set sealed/i,
  )
  assert.throws(
    () =>
      buildReleaseGateAttestation({
        commit,
        tree,
        assets,
        releaseGateSummarySha256: 'd'.repeat(64),
        platformGateReceipts: {
          ...receipts,
          windows: undefined,
        },
        assetProofs: {},
      }),
    /must include exactly|windows receipt is missing/i,
  )
})

test('release script binds Android publication to the physical-gate receipt and staged APK', () => {
  const localRelease = readFileSync(join(process.cwd(), 'scripts/local-release.mjs'), 'utf8')
  const androidBuildStart = localRelease.indexOf('function buildAndroidArtifacts(')
  const androidBuildEnd = localRelease.indexOf('\nfunction buildMacosArtifacts', androidBuildStart)
  const androidBuild = localRelease.slice(androidBuildStart, androidBuildEnd)

  assert.match(androidBuild, /validateAndroidBundleRelationship\(/)
  assert.match(androidBuild, /exactRegularFile\(path, label\)/)
  assert.doesNotMatch(androidBuild, /pathSha256\(/)
  assert.match(androidBuild, /candidateCommit/)
  assert.match(androidBuild, /candidateTree/)
  assert.doesNotMatch(androidBuild, /const componentCommit/)
  assert.doesNotMatch(androidBuild, /const componentTree/)
  assert.doesNotMatch(androidBuild, /:app:(?:assemble|bundle)Release/)
  assert.match(androidBuild, /copyFileSync\(testedApkPath,\s*apkDest\)/)
  assert.match(
    androidBuild,
    /sha256FileSync\(aabDest\)\s*!==\s*gate\.aabSha256/,
  )

  const promoteStart = localRelease.indexOf('function promoteStagedDraft(')
  const promoteEnd = localRelease.indexOf('\nfunction publishRustCrates', promoteStart)
  const promote = localRelease.slice(promoteStart, promoteEnd)
  assert.match(promote, /assertPromotableDraftSource\(tag,\s*stagedManifest\)/)

  assert.match(
    localRelease,
    /publishExactZapstoreRelease\(\{[\s\S]*?apkPath:\s*promoted\.stagedAndroidApkPath/,
  )
  assert.doesNotMatch(
    localRelease,
    /apkPath:\s*stagedRelease\.stagedAndroidApkPath/,
  )
  assert.doesNotMatch(
    localRelease,
    /apkPath:\s*stagedRelease\.stagedAndroidApkPath/,
  )
  const zapstorePublisher = readFileSync(
    join(process.cwd(), 'scripts/zapstore-release-publication.mjs'),
    'utf8',
  )
  assert.match(
    zapstorePublisher,
    /validated\.sha256\s*!==\s*sha256FileSync\(apk\)/,
  )
})

test('ordinary staging exports iOS without any App Store Connect mutation', () => {
  const localRelease = readFileSync(
    join(process.cwd(), 'scripts/local-release.mjs'),
    'utf8',
  )
  assert.match(
    localRelease,
    /requireCompleteAppRelease:\s*!allowPartial\s*&&\s*!options\.dryRun/,
  )
  const stepsStart = localRelease.indexOf('const steps = [')
  const stageStart = localRelease.indexOf('stageRelease({', stepsStart)
  const steps = localRelease.slice(stepsStart, stageStart)
  assert.ok(steps.indexOf("['windows'") < steps.indexOf("['ios'"))
  assert.ok(
    steps.indexOf('collectReleaseGateReceipts({')
      < steps.indexOf("['ios'"),
  )
  assert.match(
    localRelease,
    /function buildIosArtifacts[\s\S]*NVPN_IOS_INTERNAL_ONLY:\s*'false'/,
  )
  assert.match(
    localRelease,
    /function buildIosArtifacts[\s\S]*NVPN_RELEASE_GATE_LOG_DIR:\s*releaseGateLogDir/,
  )
  const iosBuildStart = localRelease.indexOf('function buildIosArtifacts')
  const iosBuildEnd = localRelease.indexOf(
    '\nfunction syncPlatformVersions',
    iosBuildStart,
  )
  const iosBuild = localRelease.slice(iosBuildStart, iosBuildEnd)
  assert.match(iosBuild, /'ios-export'/)
  assert.doesNotMatch(iosBuild, /ios-testflight|ios-upload|testflight-internal/)
  assert.match(
    steps,
    /buildIosArtifacts\(\{[\s\S]*releaseGateLogDir,[\s\S]*\}\)/,
  )
})

test('promotion preflights and publishes exact iOS to both TestFlight lanes and App Review', () => {
  const localRelease = readFileSync(
    join(process.cwd(), 'scripts/local-release.mjs'),
    'utf8',
  )
  const promoteStart = localRelease.indexOf('if (options.promoteDraft)')
  const promoteEnd = localRelease.indexOf('\n  const steps = [', promoteStart)
  const promote = localRelease.slice(promoteStart, promoteEnd)
  assert.ok(
    promote.indexOf('preflightIosPublication({')
      < promote.indexOf('promoteStagedDraft({'),
  )
  for (const preflight of [
    'preflightHtreeRelease({',
    'preflightGithubRelease({',
    'preflightIosPublication({',
    'preflightExactZapstorePublication({',
    'preflightRustCrates({',
  ]) {
    assert.ok(
      promote.indexOf(preflight) >= 0
        && promote.indexOf(preflight)
          < promote.indexOf('promoteStagedDraft({'),
      preflight,
    )
  }
  assert.ok(
    promote.indexOf('preflightRustCrates({')
      < promote.indexOf('publishExactIosDistribution({'),
  )
  assert.ok(
    promote.indexOf('publishExactIosDistribution({')
      < promote.indexOf('promoteStagedDraft({'),
  )
  assert.match(promote, /publishExactIosDistribution\(\{/)
  assert.match(
    promote,
    /publishExactIosDistribution\(\{[\s\S]*?beforeMutation:\s*\(\)\s*=>\s*replayCanonicalMutationGate\(\{[\s\S]*?requireTag:\s*true/,
  )

  const publisher = readFileSync(
    join(process.cwd(), 'scripts/ios-release-publication.mjs'),
    'utf8',
  )
  assert.match(publisher, /\['testflight-internal', 'put'\]/)
  assert.match(publisher, /\['testflight-internal', 'public'\]/)
  assert.match(
    publisher,
    /\[join\(repoRoot, 'scripts', 'appstore-draft'\), 'submit'\]/,
  )
  assert.match(publisher, /\['testflight-internal', 'public-status'\]/)
  assert.match(publisher, /\['appstore-draft', 'status'\]/)
  assert.match(publisher, /validateFrozenIosPublication\(/)
  assert.match(publisher, /validateIosUploadReceipt\(/)
  const promoteFunctionStart = localRelease.indexOf(
    'function promoteStagedDraft(',
  )
  const promoteFunctionEnd = localRelease.indexOf(
    '\nfunction releaseMutationEnvironment',
    promoteFunctionStart,
  )
  const promoteFunction = localRelease.slice(
    promoteFunctionStart,
    promoteFunctionEnd,
  )
  assert.match(promoteFunction, /cpSync\(stageDir,\s*finalStageDir/)
  assert.match(promoteFunction, /join\(finalStageDir,\s*name\)/)
  assert.doesNotMatch(
    promoteFunction,
    /join\(stageDir,\s*(?:'release\.json'|'manifest\.json'|name)\)/,
  )
})

test('htree promotion requires an exact private publisher identity pin', () => {
  const publisher = readFileSync(
    join(process.cwd(), 'scripts/htree-release-publication.mjs'),
    'utf8',
  )
  assert.match(publisher, /if \(!expected\)/)
  assert.match(
    publisher,
    /NVPN_HTREE_PUBLISHER_NPUB must pin the expected htree release identity/,
  )
  assert.match(publisher, /if \(expected !== npub\)/)
})

test('every mutating Apple distribution entry point requires the canonical exact-stage gate', () => {
  const releaseCommon = readFileSync(
    join(process.cwd(), 'scripts/release_common.sh'),
    'utf8',
  )
  assert.match(releaseCommon, /require_var NVPN_RELEASE_STAGE_DIR/)
  assert.doesNotMatch(releaseCommon, /NVPN_FLEET_|--fleet-/)
  assert.match(releaseCommon, /--stage-dir "\$NVPN_RELEASE_STAGE_DIR"[\s\S]*?--require-tag/)

  const iosBuild = readFileSync(
    join(process.cwd(), 'scripts/ios-build'),
    'utf8',
  )
  assert.match(
    iosBuild,
    /ios-upload\)\s*\n\s*require_release_mutation_gate/,
  )
  assert.match(
    iosBuild,
    /ios-attach-internal\)\s*\n\s*require_release_mutation_gate/,
  )
  assert.match(
    iosBuild,
    /ios-testflight\|ios-release-artifacts\)\s*\n\s*require_release_mutation_gate/,
  )

  const testflight = readFileSync(
    join(process.cwd(), 'scripts/testflight-internal'),
    'utf8',
  )
  const gate = testflight.indexOf('require_release_mutation_gate "$ROOT"')
  const network = testflight.indexOf("python3 <<'PY'")
  assert.ok(gate >= 0 && network > gate)
  assert.match(
    testflight,
    /ensure-app\|compliance\|put\|attach\|expire\|public\|public-submit\|public-attach\)/,
  )
  assert.doesNotMatch(
    testflight,
    /wait\|status\|groups\|public-status\)\s*\n\s*require_release_mutation_gate/,
  )
  assert.doesNotMatch(
    testflight,
    /preflight\)\s*\n\s*require_release_mutation_gate/,
  )

  const appstore = readFileSync(
    join(process.cwd(), 'scripts/appstore-draft'),
    'utf8',
  )
  assert.match(
    appstore,
    /put\|submit\|availability\)\s*\n\s*require_release_mutation_gate/,
  )
  assert.doesNotMatch(
    appstore,
    /status\)\s*\n\s*require_release_mutation_gate/,
  )
  assert.doesNotMatch(
    appstore,
    /preflight\)\s*\n\s*require_release_mutation_gate/,
  )
})

test('crates publication has no dirty bypass and replays exact source immediately before publish', () => {
  const publisher = readFileSync(
    join(process.cwd(), 'scripts/publish.sh'),
    'utf8',
  )
  assert.doesNotMatch(publisher, /--allow-dirty/)
  assert.match(publisher, /require_release_mutation_gate "\$REPO_DIR"/)
  assert.match(publisher, /cargo package --locked -p "\$crate"/)
  assert.match(publisher, /packageSha256/)
  assert.match(publisher, /preflight_crates_io_credentials/)
  assert.doesNotMatch(publisher, /import tomllib/)
  assert.doesNotMatch(
    publisher,
    /url = "https:\/\/crates\.io\/api\/v1\/me"/,
  )
  assert.match(
    publisher,
    /for crate in "\$\{ALL_CRATES\[@\]\}"; do[\s\S]*cargo owner --list --registry crates-io "\$crate"/,
  )
  assert.match(publisher, /verify_published_crate "\$crate"/)
  assert.match(
    publisher,
    /static\.crates\.io\/crates\/\$\{crate\}\/\$\{crate\}-\$\{version\}\.crate/,
  )
  assert.match(
    publisher,
    /for crate in "\$\{TIER_1_CRATES\[@\]\}"; do[\s\S]*package_crate_and_bind_digest "\$crate"/,
  )
  assert.match(
    publisher,
    /for crate in "\$\{TIER_2_CRATES\[@\]\}"; do[\s\S]*cargo package --locked -p "\$crate" >\/dev\/null/,
  )
  assert.match(
    publisher,
    /package_crate_and_bind_digest "\$crate"\s*\n\s*verify_exact_release_source\s*\n\s*fi\s*\n\s*if output=\$\(cargo publish --locked/,
  )
})

test('Linux publication reuses the VM-installed deb and real static-musl CLI archive', () => {
  const linuxCargo = readFileSync(join(process.cwd(), 'linux/Cargo.toml'), 'utf8')
  const localRelease = readFileSync(join(process.cwd(), 'scripts/local-release.mjs'), 'utf8')
  const githubRelease = readFileSync(join(process.cwd(), '.github/workflows/release.yml'), 'utf8')
  const linuxBuildStart = localRelease.indexOf('function buildLinuxArtifacts(')
  const linuxBuildEnd = localRelease.indexOf(
    '\nfunction ensureAndroidSdkEnv',
    linuxBuildStart,
  )
  const linuxBuild = localRelease.slice(linuxBuildStart, linuxBuildEnd)

  assert.match(linuxCargo, /\["\.\.\/target\/release\/nvpn", "usr\/bin\/nvpn", "755"\]/)
  assert.match(linuxBuild, /gatedBundlePathReceipt/)
  assert.match(linuxBuild, /host-bundle path receipt/)
  assert.match(linuxBuild, /nostr-vpn\.deb/)
  assert.match(linuxBuild, /nvpn-x86_64-unknown-linux-musl\.tar\.gz/)
  assert.match(linuxBuild, /packageInstalledByDpkg/)
  assert.match(linuxBuild, /replaceWithExactFileCopy\(gatedDebPath, debPath\)/)
  assert.match(
    linuxBuild,
    /replaceWithExactFileCopy\(arm64CliArchivePath, asset\)/,
  )
  assert.doesNotMatch(
    linuxBuild,
    /copyFileSync\(arm64CliArchivePath, asset\)/,
  )
  const verificationPlan = linuxBuild.indexOf(
    'linuxPublicationVerificationPlan({',
  )
  const canonicalVerifier = linuxBuild.indexOf(
    '[verificationPlan.verifierPath, ...verificationPlan.verifierArgs]',
  )
  const publicationCopy = linuxBuild.indexOf(
    'replaceWithExactFileCopy(gatedDebPath, debPath)',
  )
  assert.ok(
    verificationPlan >= 0
    && canonicalVerifier > verificationPlan
    && publicationCopy > canonicalVerifier,
  )
  assert.match(linuxBuild, /cwd:\s*verificationPlan\.candidateRoot/)
  assert.match(linuxBuild, /musl_archive: expectedMuslArchive/)
  assert.doesNotMatch(linuxBuild, /arm-unknown-linux-musleabihf/)
  assert.doesNotMatch(localRelease, /exactLinuxArmv6PublicationArtifact/)
  assert.doesNotMatch(githubRelease, /arm-unknown-linux-musleabihf/)
  assert.doesNotMatch(linuxBuild, /commandExists\('docker'\)/)
  assert.doesNotMatch(linuxBuild, /cargo deb/)
  assert.doesNotMatch(
    linuxBuild,
    /cp \/gated\/nvpn \/work\/dist\/nvpn/,
  )
  assert.doesNotMatch(linuxBuild, /cargo build/)
  assert.doesNotMatch(linuxBuild, /prepare-host-linux-vm-bundle\.sh/)
  assert.match(githubRelease, /cargo build --release --locked -p nvpn/)
})

test('exact artifact copy safely replaces a stale read-only destination', (context) => {
  const root = mkdtempSync(join(tmpdir(), 'nvpn-exact-copy-'))
  context.after(() => rmSync(root, { recursive: true, force: true }))
  const source = join(root, 'source')
  const destination = join(root, 'destination')
  writeFileSync(source, 'verified artifact\n')
  writeFileSync(destination, 'stale artifact\n')
  chmodSync(destination, 0o444)

  replaceWithExactFileCopy(source, destination)

  assert.equal(readFileSync(destination, 'utf8'), 'verified artifact\n')
})

test('macOS publication packages the canonical CLI from the app bundle', () => {
  const localRelease = readFileSync(
    join(process.cwd(), 'scripts/local-release.mjs'),
    'utf8',
  )
  const buildStart = localRelease.indexOf('function buildMacosArtifacts(')
  const buildEnd = localRelease.indexOf(
    '\nfunction buildIosArtifacts',
    buildStart,
  )
  const build = localRelease.slice(buildStart, buildEnd)

  assert.match(
    build,
    /const gatedCli = join\(\s*gatedAppPath,\s*'Contents',\s*'Resources',\s*'nvpn',?\s*\)/,
  )
  assert.doesNotMatch(build, /'Resources',\s*'binaries',\s*'nvpn'/)
  const identityValidation = build.indexOf('validateMacosGateSigningIdentity({')
  const packaging = build.indexOf("'macos-release-artifacts'")
  assert.ok(identityValidation >= 0 && packaging > identityValidation)
  assert.match(build, /env\.MACOS_SIGNING_IDENTITY = gateSigning\.identitySha1/)
})

test('Windows publication reuses the exact installer and CLI archive that passed the VM gate', () => {
  const localRelease = readFileSync(
    join(process.cwd(), 'scripts/local-release.mjs'),
    'utf8',
  )
  const proof = readFileSync(
    join(process.cwd(), 'scripts/windows-release-publication-proof.ps1'),
    'utf8',
  )
  const buildStart = localRelease.indexOf('function buildWindowsArtifacts(')
  const buildEnd = localRelease.indexOf(
    '\nfunction buildLinuxArtifacts',
    buildStart,
  )
  const build = localRelease.slice(buildStart, buildEnd)

  assert.match(build, /validateWindowsInstallerGateReceipt\(/)
  assert.match(build, /exactFipsPublicationCandidate\(/)
  assert.match(build, /validateWindowsPublicationFipsReceipts\(/)
  assert.match(
    build,
    /copyFileSync\(installerArtifactPath,\s*installerPath\)/,
  )
  assert.match(build, /NVPN_WINDOWS_RELEASE_ARCHIVE_PATH/)
  assert.match(build, /copyFileSync\(retainedArchivePath,\s*archivePath\)/)
  assert.match(build, /sha256FileSync\(archivePath\) !== retainedArchiveSha256/)
  assert.match(build, /validateExactZipMembers\([\s\S]*?'nvpn\.exe'[\s\S]*?'binaries\/wintun\.dll'/)
  assert.match(build, /gateReceiptPath:\s*installerReceiptPath/)
  assert.doesNotMatch(build, /ssh|scp|powershell\.exe/i)
  const hashCheck = proof.indexOf(
    '$installerSha256 = (',
  )
  const install = proof.indexOf(
    '$setup = Start-Process -FilePath $InstallerPath',
  )
  assert.ok(hashCheck >= 0 && install > hashCheck)
  assert.match(proof, /\$installer\.Length -ne \$ExpectedInstallerSize/)
  const cliSnapshot = proof.indexOf(
    "Copy-Item -LiteralPath $files.cli",
  )
  const archive = proof.indexOf('[IO.Compression.ZipFile]::Open(')
  const containment = proof.indexOf('$archiveFile.StartsWith(')
  const archiveDelete = proof.indexOf(
    'Remove-Item -Force -LiteralPath $ArchivePath',
  )
  assert.ok(cliSnapshot > hashCheck && install > cliSnapshot)
  assert.ok(archive > install)
  assert.ok(containment >= 0 && archiveDelete > containment)
  assert.match(proof, /CreateEntryFromFile\([\s\S]*?'binaries\/wintun\.dll'/)
  assert.match(proof, /finally \{[\s\S]*?unins000\.exe[\s\S]*?\$installDir, \$tempDir/)
  assert.match(proof, /!\$archiveComplete[\s\S]*?Remove-Item -Force -LiteralPath \$ArchivePath/)
  assert.match(proof, /Join-Path \$env:TEMP "nvpn-publication-payload-proof-\$proofId"/)
  assert.doesNotMatch(proof, /Join-Path \$ArtifactRoot 'publication-payload-proof'/)
  assert.match(proof, /install directory overlaps the gated publish directory/)
})

test('Linux release reclaims Docker smoke storage before host packaging', () => {
  const workflow = readFileSync(join(process.cwd(), '.github/workflows/release.yml'), 'utf8')
  const verifyJobStart = workflow.indexOf('  verify:')
  const linuxJobStart = workflow.indexOf('  build-linux-app:')
  const linuxJobEnd = workflow.indexOf('  build-windows-app:', linuxJobStart)
  const verifyJob = workflow.slice(verifyJobStart, workflow.indexOf('  build-cli:', verifyJobStart))
  const linuxJob = workflow.slice(linuxJobStart, linuxJobEnd)
  const buildx = linuxJob.indexOf('uses: docker/setup-buildx-action@v3')
  const smoke = linuxJob.indexOf('- name: Smoke launch Linux GUI')
  const cleanup = linuxJob.indexOf('- name: Reclaim Linux GUI smoke storage')
  const desktopPackage = linuxJob.indexOf('- name: Build Linux desktop package')

  assert.ok(verifyJobStart >= 0 && linuxJobStart >= 0 && linuxJobEnd > linuxJobStart)
  assert.match(verifyJob, /uses: docker\/setup-buildx-action@v3/)
  assert.ok(buildx >= 0 && smoke > buildx && cleanup > smoke && desktopPackage > cleanup)
  assert.match(linuxJob, /docker compose down --volumes --remove-orphans/)
  assert.match(linuxJob, /docker system prune --all --force --volumes/)
})

test('hosted release verification disables every private Windows lane', () => {
  const workflow = readFileSync(join(process.cwd(), '.github/workflows/release.yml'), 'utf8')
  const verifyStart = workflow.indexOf('  verify:')
  const verifyEnd = workflow.indexOf('  build-cli:', verifyStart)
  const verifyJob = workflow.slice(verifyStart, verifyEnd)

  assert.ok(verifyStart >= 0 && verifyEnd > verifyStart)
  for (const lane of [
    'NVPN_RELEASE_GATE_WINDOWS_GUI_SMOKE',
    'NVPN_RELEASE_GATE_WINDOWS_WG_EXIT_E2E',
    'NVPN_RELEASE_GATE_WINDOWS_DNS_UI_E2E',
    'NVPN_RELEASE_GATE_WINDOWS_MANUAL_JOIN_UI_E2E',
    'NVPN_RELEASE_GATE_WINDOWS_SERVICE_TOGGLE_E2E',
  ]) {
    assert.match(verifyJob, new RegExp(`${lane}: '0'`))
  }
})

test('dispatched release notes contain no build provenance text', () => {
  const workflow = readFileSync(join(process.cwd(), '.github/workflows/release.yml'), 'utf8')
  const prepareStart = workflow.indexOf('- name: Prepare release notes')
  const prepareEnd = workflow.indexOf('- name: Confirm publication remains local', prepareStart)
  const prepare = workflow.slice(prepareStart, prepareEnd)

  assert.ok(prepareStart >= 0 && prepareEnd > prepareStart)
  assert.doesNotMatch(prepare, /--commit|--built-line|--skipped-line/)
})

test('GitHub release metadata rejects same-tag asset substitution', () => {
  const exact = {
    release: {
      tagName: 'v4.1.5',
      name: 'v4.1.5',
      isDraft: false,
      isPrerelease: false,
      targetCommitish: 'a'.repeat(40),
      body: 'exact notes\n',
      assets: [
        {
          name: 'asset.zip',
          size: 42,
          digest: `sha256:${'b'.repeat(64)}`,
        },
      ],
    },
    tag: 'v4.1.5',
    commit: 'a'.repeat(40),
    notes: 'exact notes\n',
    assets: [
      {
        name: 'asset.zip',
        size: 42,
        sha256: 'b'.repeat(64),
      },
    ],
  }
  assert.doesNotThrow(() => validateGithubReleaseMetadata(exact))
  for (const mutate of [
    (value) => {
      value.release.targetCommitish = 'c'.repeat(40)
    },
    (value) => {
      value.release.assets[0].digest = `sha256:${'d'.repeat(64)}`
    },
    (value) => {
      value.release.assets[0].name = 'substitute.zip'
    },
    (value) => {
      value.release.body = 'different notes'
    },
  ]) {
    const value = structuredClone(exact)
    mutate(value)
    assert.throws(
      () => validateGithubReleaseMetadata(value),
      /GitHub release/i,
    )
  }
})

test('GitHub retry repairs only missing assets and mutable exact metadata', () => {
  const commit = 'a'.repeat(40)
  const assets = [
    {
      name: 'present.zip',
      path: '/sealed/present.zip',
      size: 42,
      sha256: 'b'.repeat(64),
    },
    {
      name: 'missing.zip',
      path: '/sealed/missing.zip',
      size: 84,
      sha256: 'c'.repeat(64),
    },
  ]
  const release = {
    tagName: 'v4.1.5',
    name: 'incomplete title',
    isDraft: true,
    isPrerelease: false,
    targetCommitish: commit,
    body: 'incomplete notes',
    assets: [
      {
        name: 'present.zip',
        size: 42,
        digest: `sha256:${'b'.repeat(64)}`,
      },
    ],
  }

  const plan = githubReleaseRepairPlan({
    release,
    tag: 'v4.1.5',
    commit,
    notes: 'exact notes\n',
    assets,
  })
  assert.equal(plan.metadataNeedsEdit, true)
  assert.deepEqual(plan.present.map(({ name }) => name), ['present.zip'])
  assert.deepEqual(plan.missing.map(({ name }) => name), ['missing.zip'])
})

test('GitHub retry never repairs a conflicting release or asset', () => {
  const commit = 'a'.repeat(40)
  const assets = [
    {
      name: 'asset.zip',
      path: '/sealed/asset.zip',
      size: 42,
      sha256: 'b'.repeat(64),
    },
  ]
  const release = {
    tagName: 'v4.1.5',
    name: 'v4.1.5',
    isDraft: false,
    isPrerelease: false,
    targetCommitish: commit,
    body: 'exact notes\n',
    assets: [
      {
        name: 'asset.zip',
        size: 42,
        digest: `sha256:${'b'.repeat(64)}`,
      },
    ],
  }
  for (const mutate of [
    (value) => {
      value.targetCommitish = 'd'.repeat(40)
    },
    (value) => {
      value.assets[0].name = 'unexpected.zip'
    },
    (value) => {
      value.assets[0].size = 43
    },
    (value) => {
      value.assets[0].digest = `sha256:${'e'.repeat(64)}`
    },
  ]) {
    const conflicting = structuredClone(release)
    mutate(conflicting)
    assert.throws(
      () => githubReleaseRepairPlan({
        release: conflicting,
        tag: 'v4.1.5',
        commit,
        notes: 'exact notes\n',
        assets,
      }),
      /GitHub release asset|target commit/i,
    )
  }
})

test('Actions cannot mutate public releases and local promotion is exact-stage gated', () => {
  const workflow = readFileSync(join(process.cwd(), '.github/workflows/release.yml'), 'utf8')
  const trigger = workflow.slice(0, workflow.indexOf('\nenv:'))
  const localRelease = readFileSync(
    join(process.cwd(), 'scripts/local-release.mjs'),
    'utf8',
  )

  assert.match(trigger, /workflow_dispatch:/)
  assert.doesNotMatch(trigger, /^\s+push:/m)
  assert.match(trigger, /locally_attested_commit:\n\s+description:[^\n]+\n\s+required: true/)
  assert.match(trigger, /locally_gated_release_cid:\n\s+description:[^\n]+\n\s+required: true/)
  assert.doesNotMatch(
    workflow,
    /ref: \$\{\{ github\.event\.inputs\.tag \}\}/,
  )
  assert.equal(
    (
      workflow.match(
        /ref: \$\{\{ github\.event\.inputs\.locally_attested_commit \}\}/g,
      ) ?? []
    ).length,
    (workflow.match(/uses: actions\/checkout@/g) ?? []).length,
  )
  assert.match(
    workflow,
    /LOCALLY_ATTESTED_COMMIT: \$\{\{ github\.event\.inputs\.locally_attested_commit \}\}/,
  )
  assert.match(workflow, /LOCALLY_ATTESTED_COMMIT.*does not match tag commit/s)
  const releaseJob = workflow.slice(workflow.indexOf('  release:'))
  assert.match(releaseJob, /htree get "\$\{LOCALLY_GATED_RELEASE_CID\}"/)
  assert.match(releaseJob, /verify-release-publication-bundle\.mjs/)
  assert.match(releaseJob, /STARTOS_CLI_VERSION: '1\.1\.0'/)
  assert.match(
    releaseJob,
    /STARTOS_CLI_SHA256: '70eff67b6e9a936acd8aaaf787b783819252ecedaa5c74d462e3b15ed4dd843a'/,
  )
  assert.match(
    releaseJob,
    /releases\/download\/start-cli\/v\$\{STARTOS_CLI_VERSION\}/,
  )
  assert.match(releaseJob, /start-cli_x86_64-linux/)
  assert.doesNotMatch(releaseJob, /actions\/download-artifact/)
  assert.doesNotMatch(releaseJob, /contents:\s*write/)
  assert.doesNotMatch(releaseJob, /action-gh-release|gh release create/)
  const promoteStart = localRelease.indexOf(
    'if (options.promoteDraft) {\n    if (!commandExists',
  )
  const promote = localRelease.slice(
    promoteStart,
    localRelease.indexOf('\n  const steps = [', promoteStart),
  )
  const mutationGate = promote.indexOf('replayCanonicalMutationGate({')
  const preflight = promote.indexOf('preflightGithubRelease({')
  const publish = promote.indexOf('publishExactGithubRelease({')
  assert.ok(preflight >= 0 && mutationGate > preflight && publish > mutationGate)
})

test('GitHub platform builds run beside verification and join before release', () => {
  const workflow = readFileSync(join(process.cwd(), '.github/workflows/release.yml'), 'utf8')
  const releaseJobStart = workflow.indexOf('  release:')
  const releaseJob = workflow.slice(releaseJobStart)

  assert.ok(releaseJobStart >= 0)
  assert.doesNotMatch(workflow, /^    needs: verify$/m)
  assert.match(releaseJob, /needs:\n      - verify/)
  for (const job of [
    'build-cli',
    'build-macos-app',
    'build-linux-app',
    'build-windows-app',
    'build-android-app',
    'build-startos',
  ]) {
    assert.match(releaseJob, new RegExp(`needs\\.${job}\\.result == 'success'`))
    assert.match(releaseJob, new RegExp(`- ${job}`))
  }
})

test('GitHub release requires and publishes both StartOS package architectures', () => {
  const workflow = readFileSync(join(process.cwd(), '.github/workflows/release.yml'), 'utf8')
  const startosJobStart = workflow.indexOf('  build-startos:')
  const releaseJobStart = workflow.indexOf('  release:')
  const startosJob = workflow.slice(startosJobStart, releaseJobStart)
  const releaseJob = workflow.slice(releaseJobStart)

  assert.ok(startosJobStart >= 0 && releaseJobStart > startosJobStart)
  assert.match(startosJob, /STARTOS_DEV_KEY/)
  assert.match(startosJob, /STARTOS_CLI_VERSION: '1\.1\.0'/)
  assert.match(startosJob, /startos_cli_sha256: 70eff67b6e9a936acd8aaaf787b783819252ecedaa5c74d462e3b15ed4dd843a/)
  assert.match(startosJob, /startos_cli_sha256: 5feebd3f9b24a130e54496040b09e78b93307a5eee0052d56cab29a12ec4c571/)
  assert.match(startosJob, /releases\/download\/start-cli\/v\$\{STARTOS_CLI_VERSION\}/)
  assert.match(startosJob, /\.startos\/build\.key\.pem/)
  assert.match(startosJob, /sha256sum --check/)
  assert.match(startosJob, /start-cli \$\{STARTOS_CLI_VERSION\}/)
  assert.match(startosJob, /target: x86/)
  assert.match(startosJob, /target: arm/)
  assert.match(startosJob, /scripts\/startos-release\.mjs/)
  assert.match(releaseJob, /needs\.build-startos\.result == 'success'/)
  assert.match(releaseJob, /- build-startos/)
  assert.doesNotMatch(releaseJob, /--built-line/)
})

test('corrected GitHub release is explicitly promoted as latest', () => {
  const publisher = readFileSync(
    join(process.cwd(), 'scripts/github-release-publication.mjs'),
    'utf8',
  )

  assert.match(publisher, /'--latest'/)
  assert.match(publisher, /'--verify-tag'/)
  assert.match(publisher, /'refs\/heads\/master'/)
  assert.match(publisher, /`refs\/tags\/\$\{tag\}`/)
  assert.match(publisher, /\['origin', 'refs\/heads\/master'/)
})

test('Windows corrected-release tags keep installer version at the marketing version', () => {
  const windowsBuild = readFileSync(join(process.cwd(), 'scripts/windows-build.ps1'), 'utf8')

  assert.match(
    windowsBuild,
    /\$Version = \(\$VersionTag\.TrimStart\("v"\) -split '\\\+', 2\)\[0\]/,
  )
  assert.match(
    windowsBuild,
    /NVPN_WINDOWS_INSTALLER_BASENAME = "nostr-vpn-\$VersionTag-windows-x64-setup"/,
  )
})

test('autoDetectWindowsVmName returns the only running Windows VM', () => {
  const name = autoDetectWindowsVmName(`
UUID                                    STATUS       IP_ADDR         NAME
{1e553d3b-024e-4799-adb0-92127659f5dd}  running      -               Windows 11
`)

  assert.equal(name, 'Windows 11')
})

test('autoDetectWindowsVmName returns null when multiple Windows VMs match', () => {
  const name = autoDetectWindowsVmName(`
UUID                                    STATUS       IP_ADDR         NAME
{1}  running      -               Windows 11
{2}  running      -               Windows ARM
`)

  assert.equal(name, null)
})

test('describeAsset maps release filenames to readable labels', () => {
  assert.equal(
    describeAsset('nostr-vpn-v0.2.27-windows-x64-setup.exe'),
    'Windows x64 installer',
  )
  assert.equal(
    describeAsset('nvpn-v0.2.27-aarch64-pc-windows-msvc.zip'),
    'Windows ARM64 CLI',
  )
  assert.equal(
    describeAsset('nostr-vpn-v4.0.97-startos-x86_64.s9pk'),
    'StartOS x86_64 package',
  )
  assert.equal(
    describeAsset('nostr-vpn-v0.3.23-linux-arm64.AppImage'),
    'Linux ARM64 AppImage',
  )
  assert.equal(
    describeAsset('nostr-vpn-v0.3.23-linux-arm64.deb'),
    'Linux ARM64 Debian package',
  )
  assert.equal(
    describeAsset('nvpn-v0.3.23-aarch64-unknown-linux-musl.tar.gz'),
    'Linux ARM64 CLI (versioned)',
  )
})

test('androidReleaseAssetName formats signed and unsigned Android asset names', () => {
  assert.equal(androidReleaseAssetName('0.3.9'), 'nostr-vpn-v0.3.9-android-arm64.apk')
  assert.equal(
    androidReleaseAssetName('v0.3.9', { extension: 'aab', signed: false }),
    'nostr-vpn-v0.3.9-android-arm64-unsigned.aab',
  )
})

test('buildReleaseManifest records staged assets with sizes', () => {
  const root = mkdtempSync(join(tmpdir(), 'nostr-vpn-release-test-'))
  const assetsDir = join(root, 'assets')
  mkdirSync(assetsDir)
  const installer = join(assetsDir, 'nostr-vpn-v0.2.27-windows-x64-setup.exe')
  const cliZip = join(assetsDir, 'nvpn-v0.2.27-x86_64-pc-windows-msvc.zip')
  writeFileSync(installer, 'installer')
  writeFileSync(cliZip, 'zip')

  const manifest = buildReleaseManifest({
    tag: 'v0.2.27',
    commit: 'abc123',
    createdAt: 1774523304,
    assetPaths: [installer, cliZip],
  })

  assert.equal(manifest.assets.length, 2)
  assert.equal(manifest.assets[0].name, 'nostr-vpn-v0.2.27-windows-x64-setup.exe')
  assert.equal(manifest.assets[1].name, 'nvpn-v0.2.27-x86_64-pc-windows-msvc.zip')
  assert.equal(manifest.assets[0].path, 'assets/nostr-vpn-v0.2.27-windows-x64-setup.exe')
  assert.equal(
    manifest.assets[0].sha256,
    createHash('sha256').update('installer').digest('hex'),
  )
})

test('buildReleaseManifestFiles writes legacy manifest alias', () => {
  const manifest = {
    id: 'v0.3.23',
    assets: [{ name: 'nostr-vpn-v0.3.23-macos-arm64.app.tar.gz' }],
  }

  const files = buildReleaseManifestFiles(manifest)
  assert.deepEqual(files.map(([name]) => name), ['release.json', 'manifest.json'])
  assert.equal(files[0][1], files[1][1])
  assert.deepEqual(JSON.parse(files[0][1]), manifest)
})

test('validateStagedReleaseTree rejects missing manifest assets', () => {
  const root = mkdtempSync(join(tmpdir(), 'nostr-vpn-release-missing-asset-test-'))
  const manifest = {
    assets: [
      {
        name: 'nostr-vpn-v4.0.77-macos-arm64.dmg',
        path: 'assets/nostr-vpn-v4.0.77-macos-arm64.dmg',
        size: 31_537_430,
      },
    ],
  }

  assert.throws(
    () => validateStagedReleaseTree(root, manifest),
    /lists missing asset: assets\/nostr-vpn-v4\.0\.77-macos-arm64\.dmg/,
  )
})

test('validateStagedReleaseTree rejects unsafe asset paths', () => {
  const root = mkdtempSync(join(tmpdir(), 'nostr-vpn-release-unsafe-asset-test-'))
  const manifest = {
    assets: [
      {
        name: 'nostr-vpn-v4.0.77-macos-arm64.dmg',
        path: '../nostr-vpn-v4.0.77-macos-arm64.dmg',
        size: 1,
      },
    ],
  }

  assert.throws(
    () => validateStagedReleaseTree(root, manifest),
    /unsafe asset path/,
  )
})

test('validateStagedReleaseTree rejects staged asset size mismatches', () => {
  const root = mkdtempSync(join(tmpdir(), 'nostr-vpn-release-size-asset-test-'))
  const assetsDir = join(root, 'assets')
  mkdirSync(assetsDir)
  writeFileSync(join(assetsDir, 'nostr-vpn-v4.0.77-macos-arm64.dmg'), 'tiny')

  const manifest = {
    assets: [
      {
        name: 'nostr-vpn-v4.0.77-macos-arm64.dmg',
        path: 'assets/nostr-vpn-v4.0.77-macos-arm64.dmg',
        size: 31_537_430,
      },
    ],
  }

  assert.throws(
    () => validateStagedReleaseTree(root, manifest),
    /size mismatch/,
  )
})

test('validateStagedReleaseTree rejects same-size staged asset substitution', () => {
  const root = mkdtempSync(join(tmpdir(), 'nostr-vpn-release-hash-asset-test-'))
  const assetsDir = join(root, 'assets')
  mkdirSync(assetsDir)
  const path = join(assetsDir, 'nostr-vpn-v4.1.5-android-arm64.apk')
  writeFileSync(path, 'sealed')
  const manifest = {
    assets: [
      {
        name: 'nostr-vpn-v4.1.5-android-arm64.apk',
        path: 'assets/nostr-vpn-v4.1.5-android-arm64.apk',
        size: 6,
        sha256: createHash('sha256').update('sealed').digest('hex'),
      },
    ],
  }

  writeFileSync(path, 'forged')
  assert.throws(
    () => validateStagedReleaseTree(root, manifest),
    /SHA-256 mismatch/,
  )
})

test('extractChangelogSection returns the matching version body', () => {
  const section = extractChangelogSection(`
# Changelog

## Unreleased

## 0.3.0 - 2026-03-31

Changes since v0.2.28.

### Added

- Admin-managed rosters.

## 0.2.28 - 2026-03-26

- Previous release.
`, 'v0.3.0')

  assert.equal(
    section,
    'Changes since v0.2.28.\n\n### Added\n\n- Admin-managed rosters.',
  )
})

test('extractChangelogSection uses the marketing version for corrected build tags', () => {
  const section = extractChangelogSection(`
# Changelog

## 4.1.4 - 2026-07-23

- Corrected the iOS App Store build.

## 4.1.3 - 2026-07-20

- Earlier release.
`, 'v4.1.4+4001006')

  assert.equal(section, '- Corrected the iOS App Store build.')
})

test('extractChangelogSection prefers corrected build notes when present', () => {
  const section = extractChangelogSection(`
# Changelog

## 4.1.4+4001006 - 2026-07-23

- Corrected build-specific notes.

## 4.1.4 - 2026-07-22

- Original marketing release.
`, 'v4.1.4+4001006')

  assert.equal(section, '- Corrected build-specific notes.')
})

test('renderReleaseNotes includes only product-facing changelog notes', () => {
  const notes = renderReleaseNotes({
    tag: 'v0.2.27',
    commit: 'abc123',
    assetNames: [
      'nostr-vpn-v0.2.27-macos-arm64.app.tar.gz',
      'nostr-vpn-v0.2.27-macos-arm64.dmg',
      'nvpn-v0.2.27-x86_64-pc-windows-msvc.zip',
    ],
    changelogText: `
# Changelog

## 0.2.27 - 2026-03-25

### Release notes

- More reliable VPN connections.

### Development

- Release note formatting.
`,
    builtLines: ['Built Windows x64 CLI on windows-builder.'],
    skippedLines: ['Linux musl CLI skipped because cross was unavailable.'],
  })

  assert.match(notes, /## Reliability across every platform/)
  assert.match(notes, /More reliable VPN connections\./)
  assert.match(notes, /### Most People Will Want/)
  assert.match(notes, /### Command Line/)
  assert.match(notes, /Windows x64 CLI/)
  assert.doesNotMatch(notes, /Release note formatting\./)
  assert.doesNotMatch(notes, /Built Windows x64 CLI on windows-builder\./)
  assert.doesNotMatch(notes, /Linux musl CLI skipped because cross was unavailable\./)
  assert.doesNotMatch(notes, /Release Build/)
  assert.doesNotMatch(notes, /Skipped or Not Built/)
})

test('renderReleaseNotes omits CLI skip boilerplate and can link assets', () => {
  const notes = renderReleaseNotes({
    tag: 'v0.3.0',
    commit: 'abc123',
    assetNames: [
      'nostr-vpn-v0.3.0-macos-arm64.app.tar.gz',
      'nostr-vpn-v0.3.0-macos-arm64.dmg',
    ],
    assetBaseUrl: 'https://github.com/mmalmi/nostr-vpn/releases/download/v0.3.0',
    skippedLines: [
      'verify skipped by CLI options.',
      'windows skipped by CLI options.',
    ],
  })

  assert.match(
    notes,
    /\[nostr-vpn-v0\.3\.0-macos-arm64\.dmg\]\(https:\/\/github\.com\/mmalmi\/nostr-vpn\/releases\/download\/v0\.3\.0\/nostr-vpn-v0\.3\.0-macos-arm64\.dmg\)/,
  )
  assert.doesNotMatch(notes, /verify skipped by CLI options/)
  assert.doesNotMatch(notes, /windows skipped by CLI options/)
})

test('renderReleaseNotes groups common app downloads before advanced files', () => {
  const notes = renderReleaseNotes({
    tag: 'v0.3.23',
    commit: 'abc123',
    assetNames: [
      'nostr-vpn-v0.3.23-android-arm64.aab',
      'nostr-vpn-v0.3.23-android-arm64.apk',
      'nostr-vpn-v0.3.23-linux-x64.AppImage',
      'nostr-vpn-v0.3.23-linux-x64.deb',
      'nostr-vpn-v0.3.23-macos-arm64.app.tar.gz',
      'nostr-vpn-v0.3.23-macos-arm64.dmg',
      'nostr-vpn-v0.3.23-startos-aarch64.s9pk',
      'nostr-vpn-v0.3.23-startos-x86_64.s9pk',
      'nostr-vpn-v0.3.23-windows-x64-setup.exe',
      'nvpn-aarch64-apple-darwin.tar.gz',
      'nvpn-v0.3.23-aarch64-apple-darwin.tar.gz',
      'nvpn-v0.3.23-x86_64-pc-windows-msvc.zip',
      'nvpn-v0.3.23-x86_64-unknown-linux-musl.tar.gz',
      'nvpn-x86_64-unknown-linux-musl.tar.gz',
    ],
  })

  assert.match(notes, /### Most People Will Want[\s\S]*Nostr VPN for macOS \(Apple Silicon\)/)
  assert.match(notes, /### Most People Will Want[\s\S]*Nostr VPN for Linux \(AppImage\)/)
  assert.match(notes, /### Most People Will Want[\s\S]*Nostr VPN for Windows/)
  assert.doesNotMatch(
    notes.match(/### Most People Will Want[\s\S]*?(?=\n### )/)?.[0] ?? '',
    /StartOS/,
  )
  assert.match(notes, /### StartOS Servers[\s\S]*Nostr VPN for StartOS \(x86_64\)/)
  assert.match(notes, /### StartOS Servers[\s\S]*Nostr VPN for StartOS \(aarch64\)/)
  assert.match(notes, /Server One and Server Pure use x86_64/)
  assert.match(notes, /### Command Line[\s\S]*macOS Apple Silicon CLI: \[nvpn-aarch64-apple-darwin\.tar\.gz\]\(assets\/nvpn-aarch64-apple-darwin\.tar\.gz\)/)
  assert.match(notes, /### Command Line[\s\S]*Linux x64 CLI: \[nvpn-x86_64-unknown-linux-musl\.tar\.gz\]\(assets\/nvpn-x86_64-unknown-linux-musl\.tar\.gz\)/)
  assert.match(notes, /### Other Files[\s\S]*Android arm64 AAB/)
  assert.match(notes, /### Other Files[\s\S]*macOS Apple Silicon updater archive/)
  assert.doesNotMatch(notes, /nvpn-v0\.3\.23-aarch64-apple-darwin\.tar\.gz/)
  assert.doesNotMatch(notes, /nvpn-v0\.3\.23-x86_64-unknown-linux-musl\.tar\.gz/)
})

test('semverFromTag strips an optional v prefix', () => {
  assert.equal(semverFromTag('v4.0.6'), '4.0.6')
  assert.equal(semverFromTag('4.0.6'), '4.0.6')
  assert.equal(semverFromTag('v4.1.4+4001006'), '4.1.4')
  assert.throws(() => semverFromTag('4.0'), /semver-shaped/)
  assert.throws(() => semverFromTag('4.0.6-alpha'), /semver-shaped/)
})

test('corrected release tags keep build metadata separate from marketing versions', () => {
  const correctedTag = 'v4.1.4+4001006'
  assert.equal(
    bumpPbxprojMarketingVersion('MARKETING_VERSION = 4.1.3;', correctedTag),
    'MARKETING_VERSION = 4.1.4;',
  )
  assert.equal(
    bumpCargoPackageVersion('[package]\nname = "example"\nversion = "4.1.3"\n\n[dependencies]\n', correctedTag),
    '[package]\nname = "example"\nversion = "4.1.4"\n\n[dependencies]\n',
  )
  const manifest = buildReleaseManifest({
    tag: correctedTag,
    commit: 'abc123',
    createdAt: 123,
    assetPaths: [],
  })
  assert.equal(manifest.tag, correctedTag)
  assert.equal(manifest.prerelease, false)
  assert.equal(
    bumpAndroidGradleVersion(
      `
android {
    defaultConfig {
        versionCode = 4010400
        versionName = "4.1.4"
    }
}
`,
      correctedTag,
      { versionCode: 4_010_401 },
    ).match(/versionCode = (\d+)/)?.[1],
    '4010401',
  )
})

test('androidVersionCode reserves two digits for corrected-release revisions', () => {
  assert.equal(androidVersionCode('4.0.6'), 4_000_600)
  assert.equal(androidVersionCode('4.0.10'), 4_001_000)
  assert.equal(androidVersionCode('4.10.0'), 4_100_000)
  assert.equal(androidVersionCode('5.0.0'), 5_000_000)
  assert.equal(androidVersionCode('4.1.4', 1), 4_010_401)
  assert.equal(androidVersionCode('4.1.5'), 4_010_500)
  assert.throws(() => androidVersionCode('4.100.0'), /minor\/patch < 100/)
  assert.throws(() => androidVersionCode('4.1.4', 100), /revision/)
})

test('bumpPbxprojMarketingVersion replaces every MARKETING_VERSION setting', () => {
  const input = `
\t\t\t\tDEVELOPMENT_TEAM = ABC123;
\t\t\t\tMARKETING_VERSION = 4.0.2;
\t\t\t\tPRODUCT_NAME = Nostr VPN;
\t\t\t\tMARKETING_VERSION = 4.0.2;
`
  const next = bumpPbxprojMarketingVersion(input, 'v4.0.6')
  assert.equal(
    next,
    input.replaceAll('MARKETING_VERSION = 4.0.2;', 'MARKETING_VERSION = 4.0.6;'),
  )
})

test('bumpAndroidGradleVersion bumps both versionCode and versionName', () => {
  const input = `
android {
    defaultConfig {
        versionCode = 40002
        versionName = "4.0.2"
    }
}
`
  const next = bumpAndroidGradleVersion(input, '4.0.6')
  assert.match(next, /versionCode = 4000600/)
  assert.match(next, /versionName = "4\.0\.6"/)
  assert.doesNotMatch(next, /4\.0\.2/)
})

test('bumpAndroidGradleVersion preserves a correction only for the same marketing version', () => {
  const corrected = `
android {
    defaultConfig {
        versionCode = 4010401
        versionName = "4.1.4"
    }
}
`
  assert.match(
    bumpAndroidGradleVersion(corrected, 'v4.1.4+4001006'),
    /versionCode = 4010401[\s\S]*versionName = "4\.1\.4"/,
  )
  assert.match(
    bumpAndroidGradleVersion(corrected, 'v4.1.5'),
    /versionCode = 4010500[\s\S]*versionName = "4\.1\.5"/,
  )
  assert.throws(
    () => bumpAndroidGradleVersion(corrected, 'v4.1.4', { versionCode: 4_010_500 }),
    /does not encode marketing version 4\.1\.4/,
  )
})

test('bumpStartosSourceVersion preserves a correction and resets it on the next version', () => {
  const corrected = "export const currentVersion = VersionInfo.of({\n  version: '4.1.4:1',\n})\n"
  assert.equal(
    bumpStartosSourceVersion(corrected, 'v4.1.4+4001006'),
    corrected,
  )
  assert.equal(
    bumpStartosSourceVersion(corrected, 'v4.1.5'),
    "export const currentVersion = VersionInfo.of({\n  version: '4.1.5:0',\n})\n",
  )
})

test('bumpCargoPackageVersion only touches [package] version', () => {
  const input = `
[package]
name = "nostr-vpn-linux"
version = "4.0.2"
edition = "2021"

[dependencies]
adw = { package = "libadwaita", version = "0.7" }
`
  const next = bumpCargoPackageVersion(input, '4.0.6')
  assert.match(next, /\[package\][\s\S]*version = "4\.0\.6"/)
  assert.match(next, /adw = \{ package = "libadwaita", version = "0\.7" \}/)
})
