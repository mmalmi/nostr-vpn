import { createHash } from 'node:crypto'

const application = {
  commit: '52a1f8eee3cf19c5bc467a3ccf39d3d6d74437f4',
  tree: '2f722bd2e0f34e7b71cae665cce74c3080c99661',
}
const fips = {
  commit: 'd0b18f2d1b2e97d42fa8460a0c70a8dffeaa2552',
  tree: '08ceced056b8592a2b2c840c4c276bf01cf28c85',
}
const authentication = {
  repository: 'mmalmi/nostr-vpn',
  workflow: '.github/workflows/apple-release-inputs.yml',
  producerCommit: '92ab2ceb349c1c0d46f68a591493fbbe9f357144',
  runId: '41902045004', jobId: 126826755088,
  jobName: 'inputs (macos)', jobConclusion: 'success',
  artifactId: 13361231905, artifactBytes: 99406197,
  artifactSha256: 'b22a6e90130e9b9f7177326c14bbc708cc2b0da6fa10bda6bfe85de0cd132b89',
}
const supportAuthentication = {
  producerCommit: 'b940ed359d394e673f287ff5c807b1afac5864e7',
  runId: '41914639900', runAttempt: '1',
  jobName: 'inputs (macos-support)', jobConclusion: 'success',
  jobId: 126870963536, artifactId: 13364154571, artifactBytes: 2576315,
  artifactSha256: '865c60c6ef954f80a22f9ee0e21c3dfe22e77d42a3cdd8cfe75f977c08e01262',
}

function requireValue(condition, message) {
  if (!condition) throw new Error(`macOS build provenance: ${message}`)
}

function requireFields(value, expected, label) {
  requireValue(value !== null && typeof value === 'object' && !Array.isArray(value),
    `${label} is missing`)
  for (const [key, expectedValue] of Object.entries(expected)) {
    requireValue(value[key] === expectedValue, `${label}.${key} differs`)
  }
}

function requireHash(value, length, label) {
  requireValue(typeof value === 'string' && new RegExp(`^[0-9a-f]{${length}}$`).test(value),
    `${label} is not an exact SHA digest`)
}

function compareKeys(left, right) {
  const a = Array.from(left, character => character.codePointAt(0))
  const b = Array.from(right, character => character.codePointAt(0))
  for (let index = 0; index < Math.min(a.length, b.length); index++) {
    if (a[index] !== b[index]) return a[index] - b[index]
  }
  return a.length - b.length
}

function asciiJsonString(value) {
  return JSON.stringify(value).replace(/[\u007f-\uffff]/g,
    character => `\\u${character.charCodeAt(0).toString(16).padStart(4, '0')}`)
}

// Match Python json.dumps(sort_keys=True, separators=(',', ':'), ensure_ascii=True).
// Admission numbers are integers: accepting floats would lose distinctions such
// as Python's 1.0 after JSON.parse and could change the producer's canonical hash.
export function canonicalMacosAdmissionJson(value) {
  if (value === null || typeof value === 'boolean') return JSON.stringify(value)
  if (typeof value === 'string') return asciiJsonString(value)
  if (typeof value === 'number') {
    requireValue(Number.isSafeInteger(value) && !Object.is(value, -0),
      'canonical JSON numbers must be safe integers')
    return String(value)
  }
  if (Array.isArray(value)) {
    return `[${Array.from(value, canonicalMacosAdmissionJson).join(',')}]`
  }
  requireValue(value !== null && typeof value === 'object'
    && [Object.prototype, null].includes(Object.getPrototypeOf(value)),
  'canonical admission contains a non-JSON value')
  return `{${Object.keys(value).sort(compareKeys).map(key =>
    `${asciiJsonString(key)}:${canonicalMacosAdmissionJson(value[key])}`).join(',')}}`
}

export function macosAdmissionCanonicalSha256(admission) {
  return createHash('sha256').update(canonicalMacosAdmissionJson(admission)).digest('hex')
}

export function validateMacosBuildProvenance(receipt) {
  requireValue(receipt !== null && typeof receipt === 'object', 'receipt is missing')
  if (receipt.receiptSchema === 1) {
    requireValue(!Object.keys(receipt).some(key => key.startsWith('hosted')
      || key === 'buildOrigin' || key === 'signedOnHost'),
    'legacy local schema cannot contain hosted provenance fields')
    requireFields(receipt, { builtOnHost: true, builtOnTestVm: false }, 'legacy local origin')
    return null
  }
  requireFields(receipt, {
    receiptSchema: 2, artifactType: 'macOS company Developer ID Release gate package',
    configuration: 'Release', companySigningVerified: true,
    builtOnHost: false, builtOnTestVm: false,
    buildOrigin: 'github-actions', signedOnHost: true,
  }, 'hosted receipt')
  requireHash(receipt.hostedAdmissionReceiptSha256, 64, 'hosted companion receipt digest')
  requireHash(receipt.hostedAdmissionCanonicalSha256, 64, 'hosted canonical admission digest')
  const admission = receipt.hostedAdmission
  requireValue(admission !== null && typeof admission === 'object' && !Array.isArray(admission),
    'hosted admission is missing')
  requireValue(macosAdmissionCanonicalSha256(admission) === receipt.hostedAdmissionCanonicalSha256,
    'hosted admission canonical digest differs')
  requireFields(admission, {
    receiptSchema: 1, artifactType: 'signed hosted macOS app admission',
    normalization: 'codesign-remove-signature-linkedit-allocation-and-share-group-v2',
  }, 'hosted admission')
  requireFields(admission.authentication, authentication, 'hosted authentication')
  requireValue(typeof admission.authentication.runAttempt === 'string'
    && /^[1-9][0-9]*$/.test(admission.authentication.runAttempt),
  'hosted authentication.runAttempt must be a positive integer string')
  requireFields(admission.buildContract, {
    rustTarget: 'aarch64-apple-darwin', rustProfile: 'release',
    realizedLockSha256: '41067773c75d291993622ac7d0a66ac77e3ce050ff6b9a646466a413f5cb065a',
  }, 'hosted build contract')
  requireFields(admission.buildContract.application, application, 'hosted application source')
  requireFields(admission.buildContract.fips, fips, 'hosted FIPS source')
  requireFields(receipt, {
    appGitSha: application.commit, appGitTree: application.tree,
    fipsGitSha: fips.commit, fipsGitTree: fips.tree,
  }, 'receipt source')
  const identity = {}
  for (const key of ['appBundleTreeSha256', 'appExecutableSha256',
    'cliExecutableSha256', 'shareFilesExecutableSha256']) {
    requireHash(receipt[key], 64, key)
    identity[key] = receipt[key]
  }
  requireFields(admission.appIdentity, identity, 'hosted signed application identity')
  requireValue(typeof receipt.signingTeam === 'string' && /^[A-Z0-9]{10}$/.test(receipt.signingTeam),
    'receipt signing team is invalid')
  requireHash(receipt.signingIdentitySha1, 40, 'receipt signing identity')
  requireHash(receipt.signerCertificateSha256, 64, 'receipt signing certificate')
  requireFields(admission.signing, {
    team: receipt.signingTeam,
    certificateSha1: receipt.signingIdentitySha1,
    certificateSha256: receipt.signerCertificateSha256,
  }, 'hosted signing identity')
  const support = receipt.hostedSupport
  requireFields(support, { receiptSchema: 1, buildOrigin: 'github-actions', signedOnHost: true },
    'hosted gate tools')
  requireHash(receipt.hostedSupportCanonicalSha256, 64, 'hosted gate-tool digest')
  requireValue(macosAdmissionCanonicalSha256(support) === receipt.hostedSupportCanonicalSha256,
    'hosted gate-tool digest differs')
  requireFields(support.authentication, supportAuthentication, 'hosted gate-tool authentication')
  for (const [key, path] of Object.entries({
    manualJoinFixtureSha256: 'fixtures/desktop_manual_join_e2e_fixture',
    manualJoinDriverSha256: 'drivers/desktop-manual-join-ax',
    serviceToggleDriverSha256: 'drivers/macos-service-toggle-ax',
    exitDnsDriverSha256: 'drivers/macos-exit-dns-ax',
  })) {
    requireHash(receipt[key], 64, key)
    requireFields(support.files?.[path], { sha256: receipt[key] }, `hosted gate tool ${path}`)
  }
  return admission
}
