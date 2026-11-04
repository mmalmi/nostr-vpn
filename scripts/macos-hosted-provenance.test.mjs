import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import test from 'node:test'

import {
  canonicalMacosAdmissionJson,
  macosAdmissionCanonicalSha256,
  validateMacosBuildProvenance,
} from './macos-hosted-provenance.mjs'

function hostedReceipt() {
  const receipt = {
    receiptSchema: 2,
    artifactType: 'macOS company Developer ID Release gate package',
    configuration: 'Release', companySigningVerified: true,
    builtOnHost: false, builtOnTestVm: false,
    buildOrigin: 'github-actions', signedOnHost: true,
    appGitSha: '52a1f8eee3cf19c5bc467a3ccf39d3d6d74437f4',
    appGitTree: '2f722bd2e0f34e7b71cae665cce74c3080c99661',
    fipsGitSha: 'd0b18f2d1b2e97d42fa8460a0c70a8dffeaa2552',
    fipsGitTree: '08ceced056b8592a2b2c840c4c276bf01cf28c85',
    appBundleTreeSha256: '1'.repeat(64), appExecutableSha256: '2'.repeat(64),
    cliExecutableSha256: '3'.repeat(64), shareFilesExecutableSha256: '4'.repeat(64),
    signingTeam: 'TESTTEAM01', signingIdentitySha1: '5'.repeat(40),
    signerCertificateSha256: '6'.repeat(64),
    hostedAdmissionReceiptSha256: '7'.repeat(64),
  }
  receipt.hostedAdmission = {
    receiptSchema: 1, artifactType: 'signed hosted macOS app admission',
    normalization: 'codesign-remove-signature-linkedit-allocation-and-share-group-v2',
    authentication: {
      repository: 'mmalmi/nostr-vpn', workflow: '.github/workflows/apple-release-inputs.yml',
      producerCommit: '92ab2ceb349c1c0d46f68a591493fbbe9f357144',
      runId: '41902045004', runAttempt: '1', jobId: 126826755088,
      jobName: 'inputs (macos)', jobConclusion: 'success',
      artifactId: 13361231905, artifactBytes: 99406197,
      artifactSha256: 'b22a6e90130e9b9f7177326c14bbc708cc2b0da6fa10bda6bfe85de0cd132b89',
    },
    buildContract: {
      application: { commit: receipt.appGitSha, tree: receipt.appGitTree },
      fips: { commit: receipt.fipsGitSha, tree: receipt.fipsGitTree },
      rustTarget: 'aarch64-apple-darwin', rustProfile: 'release',
      realizedLockSha256: '41067773c75d291993622ac7d0a66ac77e3ce050ff6b9a646466a413f5cb065a',
    },
    appIdentity: Object.fromEntries([
      'appBundleTreeSha256', 'appExecutableSha256', 'cliExecutableSha256',
      'shareFilesExecutableSha256',
    ].map(key => [key, receipt[key]])),
    signing: { team: receipt.signingTeam, certificateSha1: receipt.signingIdentitySha1,
      certificateSha256: receipt.signerCertificateSha256 },
  }
  receipt.hostedSupport = {
    receiptSchema: 1, buildOrigin: 'github-actions', signedOnHost: true,
    authentication: {
      producerCommit: 'b940ed359d394e673f287ff5c807b1afac5864e7',
      runId: '41914639900', runAttempt: '1',
      jobName: 'inputs (macos-support)', jobConclusion: 'success',
      jobId: 126870963536, artifactId: 13364154571, artifactBytes: 2576315,
      artifactSha256: '865c60c6ef954f80a22f9ee0e21c3dfe22e77d42a3cdd8cfe75f977c08e01262',
    },
    files: {},
  }
  for (const [key, path] of Object.entries({
    manualJoinFixtureSha256: 'fixtures/desktop_manual_join_e2e_fixture',
    manualJoinDriverSha256: 'drivers/desktop-manual-join-ax',
    serviceToggleDriverSha256: 'drivers/macos-service-toggle-ax',
    exitDnsDriverSha256: 'drivers/macos-exit-dns-ax',
  })) {
    receipt[key] = '8'.repeat(64)
    receipt.hostedSupport.files[path] = { sha256: receipt[key] }
  }
  return reseal(receipt)
}

function reseal(receipt) {
  receipt.hostedAdmissionCanonicalSha256 = macosAdmissionCanonicalSha256(receipt.hostedAdmission)
  if (receipt.hostedSupport) {
    receipt.hostedSupportCanonicalSha256 = macosAdmissionCanonicalSha256(receipt.hostedSupport)
  }
  return receipt
}

test('hosted gate tools require their separate job and current signed payload', () => {
  const missing = hostedReceipt()
  delete missing.hostedSupport
  assert.throws(() => validateMacosBuildProvenance(missing), /gate tools/)
  const wrongJob = hostedReceipt()
  wrongJob.hostedSupport.authentication.jobId++
  assert.throws(() => validateMacosBuildProvenance(reseal(wrongJob)), /gate-tool authentication/)
  const replaced = hostedReceipt()
  replaced.exitDnsDriverSha256 = '9'.repeat(64)
  assert.throws(() => validateMacosBuildProvenance(replaced), /gate tool/)
})

test('legacy local origin remains valid and rejects hosted fields', () => {
  const receipt = { receiptSchema: 1, builtOnHost: true, builtOnTestVm: false }
  assert.equal(validateMacosBuildProvenance(receipt), null)
  for (const field of ['hostedAdmission', 'hostedAdmissionReceiptSha256',
    'hostedAdmissionCanonicalSha256', 'hostedUnexpected', 'buildOrigin', 'signedOnHost']) {
    assert.throws(() => validateMacosBuildProvenance({ ...receipt, [field]: null }), /legacy|hosted/i)
  }
  assert.throws(() => validateMacosBuildProvenance({ ...receipt, builtOnHost: false }))
  assert.throws(() => validateMacosBuildProvenance({ ...receipt, builtOnTestVm: true }))
})

test('exact hosted admission passes with both receipt digests', () => {
  const receipt = hostedReceipt()
  assert.deepEqual(validateMacosBuildProvenance(receipt), receipt.hostedAdmission)
  for (const field of ['hostedAdmission', 'hostedAdmissionReceiptSha256',
    'hostedAdmissionCanonicalSha256', 'signedOnHost', 'buildOrigin']) {
    const missing = structuredClone(receipt)
    delete missing[field]
    assert.throws(() => validateMacosBuildProvenance(missing), field)
  }
})

test('canonical encoding matches Python ASCII escaping and nested key ordering', () => {
  const input = { z: ['é', '😀', '\u007f'], a: { z: 1, a: true } }
  const encoded = '{"a":{"a":true,"z":1},"z":["\\u00e9","\\ud83d\\ude00","\\u007f"]}'
  assert.equal(canonicalMacosAdmissionJson(input), encoded)
  assert.equal(macosAdmissionCanonicalSha256(input), createHash('sha256').update(encoded).digest('hex'))
  assert.throws(() => canonicalMacosAdmissionJson({ number: 1.5 }), /integer/i)
  assert.throws(() => canonicalMacosAdmissionJson({ number: Number.MAX_SAFE_INTEGER + 1 }), /integer/i)
  assert.throws(() => canonicalMacosAdmissionJson({ absent: undefined }), /JSON/i)
})

test('changed admission cannot pass its original canonical digest', () => {
  const receipt = hostedReceipt()
  receipt.hostedAdmission.authentication.jobConclusion = 'failure'
  assert.throws(() => validateMacosBuildProvenance(receipt), /digest/i)
})

test('rehashed cross-job, source, target, lock and normalization substitutions fail', () => {
  const mutations = [
    value => { value.authentication.producerCommit = '0'.repeat(40) },
    value => { value.authentication.repository = 'someone/nostr-vpn' },
    value => { value.authentication.workflow = '.github/workflows/other.yml' },
    value => { value.authentication.runId = '41902045005' },
    value => { value.authentication.runAttempt = '0' },
    value => { value.authentication.jobId = 126826755387 },
    value => { value.authentication.jobName = 'inputs (ios)' },
    value => { value.authentication.jobConclusion = 'failure' },
    value => { value.authentication.artifactId++ },
    value => { value.authentication.artifactBytes++ },
    value => { value.authentication.artifactSha256 = '0'.repeat(64) },
    value => { value.buildContract.application.commit = '0'.repeat(40) },
    value => { value.buildContract.application.tree = '0'.repeat(40) },
    value => { value.buildContract.fips.commit = '0'.repeat(40) },
    value => { value.buildContract.fips.tree = '0'.repeat(40) },
    value => { value.buildContract.rustTarget = 'aarch64-apple-ios' },
    value => { value.buildContract.rustProfile = 'debug' },
    value => { value.buildContract.realizedLockSha256 = '0'.repeat(64) },
    value => { value.normalization = 'strip-everything' },
  ]
  for (const mutate of mutations) {
    const receipt = hostedReceipt()
    mutate(receipt.hostedAdmission)
    assert.throws(() => validateMacosBuildProvenance(reseal(receipt)))
  }
})

test('receipt source, all executable/content identities and signer remain bound', () => {
  for (const field of ['appGitSha', 'appGitTree', 'fipsGitSha', 'fipsGitTree',
    'appBundleTreeSha256', 'appExecutableSha256', 'cliExecutableSha256',
    'shareFilesExecutableSha256', 'signingTeam', 'signingIdentitySha1',
    'signerCertificateSha256']) {
    const receipt = hostedReceipt()
    receipt[field] = 'changed'
    assert.throws(() => validateMacosBuildProvenance(receipt), field)
  }
  for (const [field, value] of [['builtOnHost', true], ['builtOnTestVm', true],
    ['signedOnHost', false], ['receiptSchema', 3]]) {
    assert.throws(() => validateMacosBuildProvenance({ ...hostedReceipt(), [field]: value }), field)
  }
})
