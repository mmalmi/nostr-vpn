import {
  constants,
  copyFileSync,
  lstatSync,
  rmSync,
  statSync,
} from 'node:fs'
import { basename, join, posix as pathPosix } from 'node:path'

import { sha256FileSync, validateReleaseGateAttestation } from './release-artifact-provenance-lib.mjs'

export { sha256FileSync }

export function replaceWithExactFileCopy(source, destination) {
  const sourceMetadata = lstatSync(source)
  if (sourceMetadata.isSymbolicLink() || !sourceMetadata.isFile()) {
    throw new Error('Exact artifact copy source must be a regular non-symlink file.')
  }
  rmSync(destination, { force: true })
  copyFileSync(source, destination, constants.COPYFILE_EXCL)
}

export function parseEnvFile(text) {
  const values = {}
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim()
    if (!line || line.startsWith('#')) {
      continue
    }

    const separator = line.indexOf('=')
    if (separator <= 0) {
      continue
    }

    const key = line.slice(0, separator).trim()
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)) {
      continue
    }

    let value = line.slice(separator + 1).trim()
    const doubleQuoted = value.startsWith('"') && value.endsWith('"')
    if (
      doubleQuoted ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1)
    }

    if (doubleQuoted) {
      value = value
        .replace(/\\n/g, '\n')
        .replace(/\\r/g, '\r')
        .replace(/\\t/g, '\t')
    }

    values[key] = value
  }

  return values
}

export function splitCsv(value) {
  return (value || '')
    .split(',')
    .map((part) => part.trim())
    .filter(Boolean)
}

export function validateCleanReleaseSource({
  status,
  headCommit,
  taggedCommit = '',
  tag = '',
}) {
  const dirty = String(status ?? '').trim()
  const head = String(headCommit ?? '').trim()
  const tagged = String(taggedCommit ?? '').trim()
  if (!head) {
    throw new Error('Release source HEAD commit is missing.')
  }
  if (dirty) {
    throw new Error(
      'Release source is dirty. Commit the exact tested candidate before building or publishing.',
    )
  }
  if (tagged && tagged !== head) {
    throw new Error(
      `Release tag ${tag || '<unknown>'} points to ${tagged}, not candidate HEAD ${head}.`,
    )
  }
  return head
}

export function validatePromotableReleaseSource({
  manifest,
  requestedTag,
  workspaceTag,
  status,
  headCommit,
  taggedCommit,
}) {
  if (!manifest || typeof manifest !== 'object') {
    throw new Error('Staged release manifest is missing.')
  }
  if (manifest.draft !== true) {
    throw new Error('Staged release is not a draft and cannot be promoted.')
  }

  const requested = normalizeTag(String(requestedTag ?? ''))
  const workspace = normalizeTag(String(workspaceTag ?? ''))
  const manifestTags = [manifest.id, manifest.title, manifest.tag]
    .map((value) => String(value ?? '').trim())
  if (manifestTags.some((value) => value !== requested)) {
    throw new Error(
      `Requested tag ${requested} does not equal all staged manifest identity fields.`,
    )
  }
  if (workspace !== requested) {
    throw new Error(
      `Workspace version ${workspace} does not equal staged manifest tag ${requested}.`,
    )
  }

  const head = validateCleanReleaseSource({
    status,
    headCommit,
  })
  const stagedCommit = String(manifest.commit ?? '').trim()
  if (!stagedCommit || stagedCommit !== head) {
    throw new Error(
      `Current HEAD ${head} does not equal staged manifest commit ${stagedCommit || '<missing>'}.`,
    )
  }
  const tagged = String(taggedCommit ?? '').trim()
  if (!tagged) {
    throw new Error(`Release tag ${requested} does not exist.`)
  }
  if (tagged !== stagedCommit) {
    throw new Error(
      `Release tag ${requested} points to ${tagged}, not staged commit ${stagedCommit}.`,
    )
  }
  return head
}

export function validateAndroidReleaseGateReceipt(
  receipt,
  {
    apkSha256,
    aabSha256,
    expectedAppGitSha,
    expectedAppGitTree,
    expectedPackage,
  } = {},
) {
  if (!receipt || typeof receipt !== 'object') {
    throw new Error('Physical Android gate receipt is missing.')
  }
  if (receipt.receiptSchema !== 2 || receipt.artifactType !== 'Android Release APK') {
    throw new Error('Physical Android gate receipt schema or artifact type is invalid.')
  }

  const testedApkSha = String(apkSha256 ?? '').trim().toLowerCase()
  if (!/^[0-9a-f]{64}$/.test(testedApkSha)) {
    throw new Error('Current Android APK SHA-256 is invalid.')
  }
  if (String(receipt.apkSha256 ?? '').trim().toLowerCase() !== testedApkSha) {
    throw new Error('Android APK bytes differ from the artifact sealed by the physical gate.')
  }
  if (
    String(receipt.installedApkSha256 ?? '').trim().toLowerCase()
    !== testedApkSha
  ) {
    throw new Error('Installed APK differs from the tested artifact sealed by the physical gate.')
  }
  const testedAabSha = String(aabSha256 ?? '').trim().toLowerCase()
  if (
    !/^[0-9a-f]{64}$/.test(testedAabSha)
    || String(receipt.aabSha256 ?? '').trim().toLowerCase()
      !== testedAabSha
    || receipt.apkDerivedFromAab !== true
    || !/^[0-9a-f]{64}$/.test(
      String(receipt.bundleReceiptSha256 ?? '').trim().toLowerCase(),
    )
    || receipt.bundletoolVersion !== '1.18.3'
    || receipt.bundletoolSha256
      !== 'a099cfa1543f55593bc2ed16a70a7c67fe54b1747bb7301f37fdfd6d91028e29'
  ) {
    throw new Error(
      'Android APK was not physically gated from the exact Play AAB.',
    )
  }
  if (
    !/^[0-9a-f]{64}$/.test(
      String(receipt.apkPathSha256 ?? '').trim().toLowerCase(),
    )
  ) {
    throw new Error('Physical Android gate receipt has no valid historical APK path hash.')
  }
  if (receipt.companySigningVerified !== true) {
    throw new Error('Physical Android gate did not verify a signed Release APK.')
  }
  const signerCertificateSha256 = String(
    receipt.signerCertificateSha256 ?? '',
  ).trim().toLowerCase()
  if (!/^[0-9a-f]{64}$/.test(signerCertificateSha256)) {
    throw new Error('Physical Android gate receipt has no valid signing certificate SHA-256.')
  }

  const appGitSha = String(receipt.appGitSha ?? '').trim()
  const appGitTree = String(receipt.appGitTree ?? '').trim()
  if (
    !/^[0-9a-f]{40}$/.test(appGitSha)
    || !/^[0-9a-f]{40}$/.test(appGitTree)
  ) {
    throw new Error(
      'Physical Android gate receipt lacks an exact component-origin SHA/tree.',
    )
  }
  if (appGitSha !== String(expectedAppGitSha ?? '').trim()) {
    throw new Error('Physical Android gate receipt has the wrong application commit.')
  }
  if (appGitTree !== String(expectedAppGitTree ?? '').trim()) {
    throw new Error('Physical Android gate receipt has the wrong application tree.')
  }
  const packageId = String(receipt.package ?? '').trim()
  if (!packageId || packageId !== String(expectedPackage ?? '').trim()) {
    throw new Error('Physical Android gate receipt has the wrong package.')
  }
  if (receipt.replacementInstall !== true) {
    throw new Error('Physical Android gate did not verify replacement installation.')
  }
  if (receipt.debuggable !== false) {
    throw new Error('Physical Android gate receipt is not for a non-debuggable Release APK.')
  }

  return {
    receiptSchema: 2,
    apkSha256: testedApkSha,
    aabSha256: testedAabSha,
    appGitSha,
    appGitTree,
    package: packageId,
    signerCertificateSha256,
  }
}

export function validateAndroidBundleRelationship(
  bundleReceipt,
  { receipt, receiptSha256, apkSha256, aabSha256 } = {},
) {
  const sha256 = (value) => /^[0-9a-f]{64}$/.test(String(value ?? '').trim())
  if (
    receiptSha256 !== receipt?.bundleReceiptSha256
    || bundleReceipt?.schema !== 1
    || bundleReceipt.relationship !== 'universal-apk-derived-from-exact-aab'
    || bundleReceipt.appGitSha !== receipt.appGitSha
    || bundleReceipt.appGitTree !== receipt.appGitTree
    || bundleReceipt.aabSha256 !== aabSha256
    || bundleReceipt.apkSha256 !== apkSha256
    || !sha256(bundleReceipt.aabPathSha256)
    || bundleReceipt.apkPathSha256 !== receipt.apkPathSha256
    || bundleReceipt.bundletoolVersion !== receipt.bundletoolVersion
    || bundleReceipt.bundletoolSha256 !== receipt.bundletoolSha256
  ) {
    throw new Error(
      'Android APK/AAB bytes differ from the bundle relationship sealed by the physical gate.',
    )
  }
}

export function validateMacosGateSigningIdentity({
  receipt,
  codesigningIdentities,
  resolvedCertificateSha256,
} = {}) {
  if (
    receipt?.receiptSchema !== 1
    || receipt.artifactType !== 'macOS company Developer ID Release gate package'
    || receipt.companySigningVerified !== true
  ) {
    throw new Error('macOS publication received the wrong gate receipt.')
  }
  const identitySha1 = String(receipt.signingIdentitySha1 ?? '').trim().toLowerCase()
  const signingTeam = String(receipt.signingTeam ?? '').trim()
  const signerCertificateSha256 = String(
    receipt.signerCertificateSha256 ?? '',
  ).trim().toLowerCase()
  if (!/^[0-9a-f]{40}$/.test(identitySha1)) {
    throw new Error('macOS gate receipt has no valid signing identity SHA-1.')
  }
  if (!/^[A-Z0-9]{10}$/.test(signingTeam)) {
    throw new Error('macOS gate receipt has no valid signing team.')
  }
  if (!/^[0-9a-f]{64}$/.test(signerCertificateSha256)) {
    throw new Error('macOS gate receipt has no valid signer certificate SHA-256.')
  }
  const matchingTeams = String(codesigningIdentities ?? '')
    .split(/\r?\n/)
    .flatMap((line) => {
      const match = line.match(
        /^\s*\d+\)\s+([0-9a-f]{40})\s+"(Developer ID Application: .+)"\s*$/i,
      )
      if (!match || match[1].toLowerCase() !== identitySha1) return []
      return [match[2].match(/\(([A-Z0-9]{10})\)$/)?.[1] ?? '']
    })
  if (matchingTeams.length !== 1) {
    throw new Error(
      'macOS gate signing identity does not resolve to exactly one valid Developer ID identity.',
    )
  }
  if (matchingTeams[0] !== signingTeam) {
    throw new Error('Resolved macOS signing identity team differs from the gate receipt.')
  }
  if (
    String(resolvedCertificateSha256 ?? '').trim().toLowerCase()
    !== signerCertificateSha256
  ) {
    throw new Error('Resolved macOS signing certificate differs from the gate receipt.')
  }
  return {
    identitySha1: identitySha1.toUpperCase(),
    signingTeam,
    signerCertificateSha256,
  }
}

export function zapstorePublicationRequired({
  cliRequired = false,
  envValue = '',
} = {}) {
  return Boolean(cliRequired) || /^(1|true|yes|on)$/i.test(String(envValue).trim())
}

export function zapstorePublicationPrerequisites(
  prerequisites = {},
  { required = false } = {},
) {
  const labels = {
    apk: 'APK',
    zsp: 'zsp tool',
    nak: 'nak verification tool',
    signing: 'signing configuration',
    config: 'Zapstore config',
    publisher: 'publisher identity',
    relays: 'relays configuration',
  }
  const missing = Object.entries(labels)
    .filter(([name]) => !prerequisites[name])
    .map(([, label]) => label)
  if (required && missing.length > 0) {
    throw new Error(
      `Required Zapstore publication unavailable: missing ${missing.join(', ')}.`,
    )
  }
  return {
    available: missing.length === 0,
    missing,
  }
}

export function validateZapstoreApkMetadata(
  metadata,
  {
    expectedVersion,
    expectedVersionCode,
    expectedPackageId,
    expectedCertificateFingerprint = '',
  } = {},
) {
  const packageId = String(metadata?.package_id ?? '').trim()
  const versionName = String(metadata?.version_name ?? '').trim()
  const versionCode = Number(metadata?.version_code)
  const certificateFingerprint = String(metadata?.cert_fingerprint ?? '').trim()
  const sha256 = String(metadata?.sha256 ?? '').trim().toLowerCase()
  const architectures = Array.isArray(metadata?.architectures)
    ? metadata.architectures.map((value) => String(value).trim())
    : []

  if (!packageId || packageId !== String(expectedPackageId ?? '').trim()) {
    throw new Error(
      `Zapstore APK package ${packageId || '<missing>'} does not match ${expectedPackageId || '<missing>'}.`,
    )
  }
  if (!versionName || versionName !== String(expectedVersion ?? '').trim()) {
    throw new Error(
      `Zapstore APK version ${versionName || '<missing>'} does not match ${expectedVersion || '<missing>'}.`,
    )
  }
  if (
    !Number.isSafeInteger(versionCode)
    || versionCode <= 0
    || versionCode !== Number(expectedVersionCode)
  ) {
    throw new Error(
      `Zapstore APK version code ${Number.isFinite(versionCode) ? versionCode : '<missing>'} does not match ${expectedVersionCode || '<missing>'}.`,
    )
  }
  if (!architectures.includes('arm64-v8a')) {
    throw new Error('Zapstore APK does not contain the required arm64-v8a architecture.')
  }
  if (!certificateFingerprint) {
    throw new Error('Zapstore APK is not signed with an Android certificate.')
  }
  if (
    expectedCertificateFingerprint
    && certificateFingerprint.replaceAll(':', '').toLowerCase()
      !== String(expectedCertificateFingerprint)
        .replaceAll(':', '')
        .toLowerCase()
  ) {
    throw new Error(
      'Zapstore APK signing certificate differs from the frozen release manifest.',
    )
  }
  if (!/^[0-9a-f]{64}$/.test(sha256)) {
    throw new Error('Zapstore APK metadata does not contain a valid SHA-256 hash.')
  }

  return {
    packageId,
    versionName,
    versionCode,
    certificateFingerprint,
    sha256,
  }
}

function hasEventTag(event, name, value = null) {
  if (!Array.isArray(event?.tags)) {
    return false
  }
  return event.tags.some(
    (tag) =>
      Array.isArray(tag)
      && tag[0] === name
      && (value == null || String(tag[1] ?? '') === String(value)),
  )
}

export function validateZapstoreRelayPublication({
  appEvents = [],
  releaseEvents = [],
  assetEvents = [],
  expected = {},
} = {}) {
  const {
    pubkey,
    packageId,
    versionName,
    versionCode,
    sha256,
    certificateFingerprint,
  } = expected
  const common = (event, kind) =>
    event?.kind === kind
    && event?.pubkey === pubkey
    && typeof event?.id === 'string'
    && event.id.length > 0

  const asset = assetEvents.find(
    (event) =>
      common(event, 3063)
      && hasEventTag(event, 'i', packageId)
      && hasEventTag(event, 'version', versionName)
      && hasEventTag(event, 'version_code', versionCode)
      && hasEventTag(event, 'x', sha256)
      && hasEventTag(event, 'apk_certificate_hash', certificateFingerprint)
      && hasEventTag(event, 'f', 'android-arm64-v8a')
      && hasEventTag(event, 'url'),
  )
  if (!asset) {
    throw new Error('Zapstore relay does not contain the exact published software asset.')
  }

  const release = releaseEvents.find(
    (event) =>
      common(event, 30063)
      && hasEventTag(event, 'i', packageId)
      && hasEventTag(event, 'version', versionName)
      && hasEventTag(event, 'd', `${packageId}@${versionName}`)
      && hasEventTag(event, 'c', 'main')
      && hasEventTag(event, 'f', 'android-arm64-v8a')
      && hasEventTag(event, 'e', asset.id),
  )
  if (!release) {
    throw new Error('Zapstore relay does not contain the exact published software release.')
  }

  const app = appEvents.find(
    (event) =>
      common(event, 32267)
      && hasEventTag(event, 'd', packageId)
      && hasEventTag(event, 'f', 'android-arm64-v8a'),
  )
  if (!app) {
    throw new Error('Zapstore relay does not contain the published application metadata.')
  }

  return { app, release, asset }
}

export function deterministicBuildEnv(env = {}, { sourceDateEpoch = null } = {}) {
  const epoch = String(sourceDateEpoch ?? env.SOURCE_DATE_EPOCH ?? '0').trim()
  if (!/^\d+$/.test(epoch)) {
    throw new Error(`SOURCE_DATE_EPOCH must be a Unix timestamp, got: ${epoch || '<empty>'}`)
  }

  return {
    ...env,
    SOURCE_DATE_EPOCH: epoch,
    CARGO_INCREMENTAL: env.CARGO_INCREMENTAL || '0',
    ZERO_AR_DATE: env.ZERO_AR_DATE || '1',
    LC_ALL: env.LC_ALL || 'C',
    TZ: env.TZ || 'UTC',
  }
}

export function windowsSshTransportArgs(env = {}, { connectTimeout = 10 } = {}) {
  const args = ['-o', 'BatchMode=yes', '-o', `ConnectTimeout=${connectTimeout}`]
  const proxyCommand = String(env.NVPN_WINDOWS_SSH_PROXY_COMMAND || '').trim()
  const jumpHost = String(env.NVPN_WINDOWS_SSH_JUMP || '').trim()
  if (proxyCommand) {
    args.push('-o', `ProxyCommand=${proxyCommand}`)
  } else if (jumpHost) {
    args.push('-J', jumpHost)
  }
  return args
}

export function linuxReleaseTargetsForDockerPlatform(platform) {
  const normalized = String(platform || '').trim()
  const match = normalized.match(/^linux\/([^/]+)(?:\/[^/]+)?$/)
  if (!match) {
    throw new Error(`Unsupported Linux Docker platform: ${normalized || '<empty>'}`)
  }

  const dockerArch = match[1]
  if (dockerArch === 'arm64' || dockerArch === 'aarch64') {
    return {
      linuxArchSuffix: 'arm64',
      muslTriple: 'aarch64-unknown-linux-musl',
    }
  }

  if (dockerArch === 'amd64' || dockerArch === 'x86_64') {
    return {
      linuxArchSuffix: 'x64',
      muslTriple: 'x86_64-unknown-linux-musl',
    }
  }

  throw new Error(`Unsupported Linux Docker architecture: ${dockerArch}`)
}

export function shouldBlockLocalLinuxAmd64Qemu({ platform, hostPlatform, hostArch, allowQemu = false }) {
  if (allowQemu) {
    return false
  }

  return platform === 'linux/amd64' && hostPlatform === 'darwin' && hostArch === 'arm64'
}

export function validateReleaseAssetSet(
  assetNames,
  { allowLinuxArm64DesktopOnly = false, requireCompleteAppRelease = false } = {},
) {
  const names = [...assetNames]
  const hasMacosZip = names.some((name) => /^nostr-vpn-.*-macos-arm64\.zip$/.test(name))
  const hasMacosDmg = names.some((name) => /^nostr-vpn-.*-macos-arm64\.dmg$/.test(name))
  const hasMacosUpdater = names.some((name) => /^nostr-vpn-.*-macos-arm64\.app\.tar\.gz$/.test(name))
  const hasLinuxX64Desktop = names.some((name) => /^nostr-vpn-.*-linux-x64\.(AppImage|deb)$/.test(name))
  const hasLinuxArm64Desktop = names.some((name) => /^nostr-vpn-.*-linux-arm64\.(AppImage|deb)$/.test(name))
  const hasWindowsX64Setup = names.some((name) => /^nostr-vpn-.*-windows-x64-setup\.exe$/.test(name))
  const hasSignedAndroidApk = names.some((name) => /^nostr-vpn-.*-android-arm64\.apk$/.test(name))
  const hasUnsignedAndroid = names.some((name) => /^nostr-vpn-.*-android-arm64-unsigned\.(apk|aab)$/.test(name))
  const hasStartosX86 = names.some((name) => /^nostr-vpn-.*-startos-x86_64\.s9pk$/.test(name))
  const hasStartosArm = names.some((name) => /^nostr-vpn-.*-startos-aarch64\.s9pk$/.test(name))
  const hasLinuxX64Cli = names.some((name) => /-x86_64-unknown-linux-musl\.tar\.gz$/.test(name))
  const hasLinuxArm64Cli = names.some((name) => /-aarch64-unknown-linux-musl\.tar\.gz$/.test(name))

  if (names.some((name) => /(?:armv6|arm-unknown-linux-musleabihf)/.test(name))) {
    throw new Error('Public releases must not contain private-fleet ARMv6 artifacts.')
  }

  if (hasMacosZip) {
    throw new Error(
      'Release includes a macOS .zip app archive. Ship a signed/notarized .dmg for users and a signed/notarized .app.tar.gz for the updater instead.',
    )
  }

  if (hasMacosDmg && !hasMacosUpdater) {
    throw new Error(
      'Release includes a macOS .dmg but no macOS .app.tar.gz updater archive.',
    )
  }

  if (hasLinuxArm64Desktop && !hasLinuxX64Desktop && !allowLinuxArm64DesktopOnly) {
    throw new Error(
      'Release has Linux ARM64 desktop artifacts but no Linux x64 desktop artifacts. Build Linux x64 on a native amd64 builder, remove the ARM64 desktop artifacts, or set NVPN_ALLOW_LINUX_ARM64_DESKTOP_ONLY=1.',
    )
  }

  if (hasUnsignedAndroid) {
    throw new Error(
      'Release includes unsigned Android artifacts. Configure Android signing for public releases.',
    )
  }

  if (requireCompleteAppRelease) {
    const missing = []
    if (!hasMacosDmg) {
      missing.push('macOS DMG')
    }
    if (!hasMacosUpdater) {
      missing.push('macOS updater archive')
    }
    if (!hasLinuxX64Desktop) {
      missing.push('Linux x64 desktop package')
    }
    if (!hasLinuxX64Cli) {
      missing.push('Linux x64 CLI')
    }
    if (!hasLinuxArm64Cli) {
      missing.push('Linux ARM64 CLI')
    }
    if (!hasWindowsX64Setup) {
      missing.push('Windows x64 installer')
    }
    if (!hasSignedAndroidApk) {
      missing.push('signed Android APK')
    }
    if (!hasStartosX86) {
      missing.push('StartOS x86_64 package')
    }
    if (!hasStartosArm) {
      missing.push('StartOS aarch64 package')
    }
    if (missing.length > 0) {
      throw new Error(`Release is missing required app artifact(s): ${missing.join(', ')}.`)
    }
  }
}

export function validatePromotableReleaseManifest(manifest) {
  if (!manifest || !Array.isArray(manifest.assets)) {
    throw new Error('Staged release manifest has no asset list.')
  }
  validateReleaseAssetSet(
    manifest.assets.map((asset) => basename(asset.path || '')),
    { requireCompleteAppRelease: true },
  )
  const gate = manifest.android_release_gate
  if (!gate || typeof gate !== 'object') {
    throw new Error('Staged release has no physical Android gate provenance.')
  }
  const apkAsset = manifest.assets.find((asset) => asset.path === gate.apk_path)
  if (
    !apkAsset
    || !/^[0-9a-f]{64}$/.test(String(apkAsset.sha256 ?? ''))
    || apkAsset.sha256 !== gate.apk_sha256
  ) {
    throw new Error('Physical Android gate APK does not match the staged release asset.')
  }
  const attestation = validateReleaseGateAttestation(manifest)
  const androidSourceMatches =
    gate.app_git_sha === manifest.commit
    && gate.app_git_tree === attestation.app_git_tree
  const androidSourceProof = attestation.platform_source_equivalence?.android
  if (
    gate.receipt_schema !== 2
    || (
      !androidSourceMatches
      && (
        gate.source_equivalence?.changed_paths_sha256
          !== androidSourceProof?.changed_paths_sha256
        || gate.app_git_sha !== androidSourceProof?.receipt_app_git_sha
        || gate.app_git_tree !== androidSourceProof?.receipt_app_git_tree
      )
    )
    || !String(gate.package ?? '').trim()
    || !/^[0-9a-f]{64}$/.test(String(gate.signer_certificate_sha256 ?? ''))
  ) {
    throw new Error(
      'Staged physical Android gate does not match the current release candidate.',
    )
  }
}

export function readWorkspaceVersionTag(cargoTomlText) {
  const match = cargoTomlText.match(
    /^\[workspace\.package\][\s\S]*?^version\s*=\s*"([^"\n]+)"/m,
  )
  if (!match) {
    throw new Error('Could not find [workspace.package] version in Cargo.toml')
  }

  return normalizeTag(match[1])
}

export function normalizeTag(value) {
  if (!value || !value.trim()) {
    throw new Error('Release tag must not be empty')
  }

  return value.startsWith('v') ? value : `v${value}`
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

export function extractChangelogSection(changelogText, tag) {
  const taggedVersion = normalizeTag(tag).replace(/^v/, '')
  const marketingVersion = semverFromTag(tag)
  for (const version of new Set([taggedVersion, marketingVersion])) {
    const headingPattern = new RegExp(
      `^##\\s+${escapeRegExp(version)}(?:\\s+-\\s+.*)?\\s*$`,
      'm',
    )
    const headingMatch = changelogText.match(headingPattern)
    if (!headingMatch || headingMatch.index == null) {
      continue
    }

    const sectionStart = headingMatch.index + headingMatch[0].length
    const remainder = changelogText.slice(sectionStart).replace(/^\r?\n/, '')
    const nextHeadingMatch = remainder.match(/^##\s+/m)
    const section = nextHeadingMatch ? remainder.slice(0, nextHeadingMatch.index) : remainder
    const trimmed = section.trim()
    return trimmed || null
  }
  return null
}

function extractProductReleaseNotes(changelogSection, tag) {
  if (!changelogSection) {
    return null
  }
  const heading = changelogSection.match(/^###\s+Release notes\s*$/mi)
  if (!heading || heading.index == null) {
    throw new Error(
      `Changelog ${normalizeTag(tag)} must include a product-facing "### Release notes" section.`,
    )
  }
  const remainder = changelogSection
    .slice(heading.index + heading[0].length)
    .replace(/^\r?\n/, '')
  const nextHeading = remainder.match(/^###\s+/m)
  const notes = (nextHeading ? remainder.slice(0, nextHeading.index) : remainder).trim()
  if (!notes) {
    throw new Error(`Changelog ${normalizeTag(tag)} has empty product release notes.`)
  }
  return notes
}

/**
 * "v4.0.6" / "4.0.6" / "v4.0.6+4000007" → "4.0.6".
 * Build metadata identifies a corrected release artifact without changing the
 * platform marketing version. Prerelease tags remain intentionally unsupported.
 */
export function semverFromTag(tag) {
  const stripped = normalizeTag(tag).replace(/^v/, '')
  const match = stripped.match(
    /^(\d+\.\d+\.\d+)(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/,
  )
  if (!match) {
    throw new Error(`Release tag must be a semver-shaped string, got "${tag}"`)
  }
  return match[1]
}

export function parseReleaseRevision(value, { platform = 'Release' } = {}) {
  const text = String(value ?? '').trim()
  if (!/^\d{1,2}$/.test(text)) {
    throw new Error(`${platform} revision must be an integer from 0 through 99, got "${text}"`)
  }
  return Number(text)
}

/**
 * Encode a semver plus a two-digit corrected-release revision as an Android
 * versionCode:
 *   "4.0.6", revision 0 → 4_00_06_00 = 4000600
 *   "4.1.4", revision 1 → 4_01_04_01 = 4010401
 * Each minor/patch/revision component is allotted two digits.
 */
export function androidVersionCode(version, revision = 0) {
  const parts = semverFromTag(version).split('.').map(Number)
  if (parts.some((value, index) => index > 0 && value >= 100)) {
    throw new Error(`Android versionCode encoding requires minor/patch < 100, got ${version}`)
  }
  const [major, minor, patch] = parts
  const parsedRevision = parseReleaseRevision(revision, { platform: 'Android' })
  const code = (major * 10_000 + minor * 100 + patch) * 100 + parsedRevision
  if (!Number.isSafeInteger(code) || code <= 0 || code > 2_100_000_000) {
    throw new Error(`Android versionCode is outside the supported range: ${code}`)
  }
  return code
}

/**
 * Replace every `MARKETING_VERSION = X.Y.Z;` in an Xcode pbxproj. Returns the
 * updated text. Both Debug and Release configs share the same setting in our
 * project, so a global replace is the right scope.
 */
export function bumpPbxprojMarketingVersion(pbxprojText, version) {
  const semver = semverFromTag(version)
  return pbxprojText.replace(/(\bMARKETING_VERSION\s*=\s*)[^;]+(;)/g, `$1${semver}$2`)
}

/**
 * Sync `versionCode = N` and `versionName = "X.Y.Z"` in an Android
 * build.gradle.kts to match the workspace version.
 */
export function bumpAndroidGradleVersion(gradleText, version, { versionCode = null } = {}) {
  const semver = semverFromTag(version)
  const baseCode = androidVersionCode(semver)
  let code = baseCode

  if (versionCode != null && String(versionCode).trim() !== '') {
    code = Number(versionCode)
    if (!Number.isSafeInteger(code) || code <= 0 || code > 2_100_000_000) {
      throw new Error(`Android versionCode must be a positive supported integer, got "${versionCode}"`)
    }
    if (Math.floor(code / 100) !== Math.floor(baseCode / 100)) {
      throw new Error(
        `Android versionCode ${code} does not encode marketing version ${semver}`,
      )
    }
  } else {
    const currentVersion = gradleText.match(/\bversionName\s*=\s*"([^"]+)"/)?.[1]
    const currentCodeText = gradleText.match(/\bversionCode\s*=\s*(\d+)/)?.[1]
    const currentCode = currentCodeText == null ? null : Number(currentCodeText)
    if (
      currentVersion === semver &&
      Number.isSafeInteger(currentCode) &&
      currentCode >= baseCode &&
      currentCode <= baseCode + 99
    ) {
      code = currentCode
    }
  }

  return gradleText
    .replace(/(\bversionCode\s*=\s*)\d+/g, `$1${code}`)
    .replace(/(\bversionName\s*=\s*")[^"]+(")/g, `$1${semver}$2`)
}

/**
 * Keep a StartOS correction revision while marketing version is unchanged,
 * then reset it to zero for the next normal marketing release.
 */
export function bumpStartosSourceVersion(sourceText, version, { revision = null } = {}) {
  const semver = semverFromTag(version)
  const currentMatch = String(sourceText).match(/^\s*version:\s*'(\d+\.\d+\.\d+):(\d+)'/m)
  let nextRevision = 0
  if (revision != null && String(revision).trim() !== '') {
    nextRevision = parseReleaseRevision(revision, { platform: 'StartOS' })
  } else if (currentMatch?.[1] === semver) {
    nextRevision = parseReleaseRevision(currentMatch[2], { platform: 'StartOS' })
  }
  return sourceText.replace(
    /^(\s*version:\s*')[^'\n]+(')/m,
    `$1${semver}:${nextRevision}$2`,
  )
}

/**
 * Replace `version = "X.Y.Z"` inside the first `[package]` table of a
 * Cargo.toml. Used for the `linux/` crate which is excluded from the workspace
 * (so workspace `[workspace.package].version` doesn't reach it).
 */
export function bumpCargoPackageVersion(cargoTomlText, version) {
  const semver = semverFromTag(version)
  const match = cargoTomlText.match(/^\[package\]\s*\n([\s\S]*?)(?=^\[)/m)
  if (!match) {
    throw new Error('Could not find [package] table in Cargo.toml')
  }
  const original = match[0]
  if (!/(\nversion\s*=\s*")[^"]+(")/.test(original)) {
    throw new Error('Could not find version field inside [package] table')
  }
  const replaced = original.replace(/(\nversion\s*=\s*")[^"]+(")/, `$1${semver}$2`)
  return cargoTomlText.replace(original, replaced)
}

export function autoDetectWindowsVmName(prlctlListOutput) {
  const candidates = []
  for (const line of prlctlListOutput.split(/\r?\n/)) {
    const trimmed = line.trim()
    if (!trimmed.startsWith('{')) {
      continue
    }

    const match = trimmed.match(/^\{[^}]+\}\s+(\S+)\s+\S+\s+(.+)$/)
    if (!match) {
      continue
    }

    const status = match[1].toLowerCase()
    const name = match[2].trim()
    if ((status === 'running' || status === 'suspended') && /windows/i.test(name)) {
      candidates.push(name)
    }
  }

  return candidates.length === 1 ? candidates[0] : null
}

export function describeAsset(name) {
  if (/^nostr-vpn-.*-macos-arm64\.zip$/.test(name)) {
    return 'macOS Apple Silicon legacy app archive'
  }
  if (/^nostr-vpn-.*-macos-arm64\.dmg$/.test(name)) {
    return 'macOS Apple Silicon disk image'
  }
  if (/^nostr-vpn-.*-macos-arm64\.app\.tar\.gz$/.test(name)) {
    return 'macOS Apple Silicon updater archive'
  }
  if (/^nostr-vpn-.*-linux-x64\.AppImage$/.test(name)) {
    return 'Linux x64 AppImage'
  }
  if (/^nostr-vpn-.*-linux-x64\.deb$/.test(name)) {
    return 'Linux x64 Debian package'
  }
  if (/^nostr-vpn-.*-linux-arm64\.AppImage$/.test(name)) {
    return 'Linux ARM64 AppImage'
  }
  if (/^nostr-vpn-.*-linux-arm64\.deb$/.test(name)) {
    return 'Linux ARM64 Debian package'
  }
  if (/^nostr-vpn-.*-windows-x64-setup\.exe$/.test(name)) {
    return 'Windows x64 installer'
  }
  if (/^nostr-vpn-.*-windows-arm64-setup\.exe$/.test(name)) {
    return 'Windows ARM64 installer'
  }
  if (/^nostr-vpn-.*-android-arm64(?:-unsigned)?\.apk$/.test(name)) {
    return name.includes('-unsigned.') ? 'Android arm64 APK (unsigned)' : 'Android arm64 APK'
  }
  if (/^nostr-vpn-.*-android-arm64(?:-unsigned)?\.aab$/.test(name)) {
    return name.includes('-unsigned.') ? 'Android arm64 AAB (unsigned)' : 'Android arm64 AAB'
  }
  if (/^nostr-vpn-.*-startos-x86_64\.s9pk$/.test(name)) {
    return 'StartOS x86_64 package'
  }
  if (/^nostr-vpn-.*-startos-aarch64\.s9pk$/.test(name)) {
    return 'StartOS aarch64 package'
  }
  if (/^nvpn-.*-aarch64-apple-darwin\.tar\.gz$/.test(name)) {
    return name.startsWith('nvpn-v') ? 'Apple Silicon CLI (versioned)' : 'Apple Silicon CLI'
  }
  if (/^nvpn-.*-x86_64-unknown-linux-musl\.tar\.gz$/.test(name)) {
    return name.startsWith('nvpn-v') ? 'Linux x64 CLI (versioned)' : 'Linux x64 CLI'
  }
  if (/^nvpn-.*-aarch64-unknown-linux-musl\.tar\.gz$/.test(name)) {
    return name.startsWith('nvpn-v') ? 'Linux ARM64 CLI (versioned)' : 'Linux ARM64 CLI'
  }
  if (/^nvpn-.*-x86_64-pc-windows-msvc\.zip$/.test(name)) {
    return 'Windows x64 CLI'
  }
  if (/^nvpn-.*-aarch64-pc-windows-msvc\.zip$/.test(name)) {
    return 'Windows ARM64 CLI'
  }

  return name
}

function firstMatchingAsset(assetNames, patterns) {
  for (const pattern of patterns) {
    const name = assetNames.find((assetName) => pattern.test(assetName))
    if (name) {
      return name
    }
  }
  return null
}

function assetReference(name, assetBaseUrl = '') {
  if (assetBaseUrl) {
    return `[${name}](${assetBaseUrl}/${encodeURIComponent(name)})`
  }
  return `[${name}](assets/${encodeURIComponent(name)})`
}

function pushAssetLine(lines, usedAssets, assetNames, label, patterns, assetBaseUrl = '') {
  const name = firstMatchingAsset(assetNames, patterns)
  if (!name) {
    return null
  }

  usedAssets.add(name)
  lines.push(`- ${label}: ${assetReference(name, assetBaseUrl)}`)
  return name
}

function markMatchingAssetsUsed(usedAssets, assetNames, patterns) {
  for (const name of assetNames) {
    if (patterns.some((pattern) => pattern.test(name))) {
      usedAssets.add(name)
    }
  }
}

function pushDownloadSections(lines, assetNames, assetBaseUrl = '') {
  const sortedNames = [...assetNames].sort((left, right) => left.localeCompare(right))
  const usedAssets = new Set()

  lines.push('## Downloads', '', '### Most People Will Want', '')

  pushAssetLine(lines, usedAssets, sortedNames, 'Nostr VPN for macOS (Apple Silicon)', [
    /^nostr-vpn-.*-macos-arm64\.dmg$/,
  ], assetBaseUrl)
  pushAssetLine(lines, usedAssets, sortedNames, 'Nostr VPN for Linux (AppImage)', [
    /^nostr-vpn-.*-linux-x64\.AppImage$/,
  ], assetBaseUrl)
  pushAssetLine(lines, usedAssets, sortedNames, 'Nostr VPN for Debian/Ubuntu (.deb)', [
    /^nostr-vpn-.*-linux-x64\.deb$/,
  ], assetBaseUrl)
  pushAssetLine(lines, usedAssets, sortedNames, 'Nostr VPN for Windows', [
    /^nostr-vpn-.*-windows-x64-setup\.exe$/,
  ], assetBaseUrl)
  pushAssetLine(lines, usedAssets, sortedNames, 'Nostr VPN for Android', [
    /^nostr-vpn-.*-android-arm64\.apk$/,
  ], assetBaseUrl)

  const startosLines = []
  pushAssetLine(startosLines, usedAssets, sortedNames, 'Nostr VPN for StartOS (x86_64)', [
    /^nostr-vpn-.*-startos-x86_64\.s9pk$/,
  ], assetBaseUrl)
  pushAssetLine(startosLines, usedAssets, sortedNames, 'Nostr VPN for StartOS (aarch64)', [
    /^nostr-vpn-.*-startos-aarch64\.s9pk$/,
  ], assetBaseUrl)

  if (startosLines.length > 0) {
    lines.push(
      '',
      '### StartOS Servers',
      '',
      'Server One and Server Pure use x86_64; use aarch64 only for an ARM64 StartOS host.',
      '',
      ...startosLines,
    )
  }

  const cliLines = []
  const addCliAsset = (label, preferredPatterns, duplicatePatterns = preferredPatterns) => {
    const name = firstMatchingAsset(sortedNames, preferredPatterns)
    if (!name) {
      return
    }
    usedAssets.add(name)
    markMatchingAssetsUsed(usedAssets, sortedNames, duplicatePatterns)
    cliLines.push(`- ${label}: ${assetReference(name, assetBaseUrl)}`)
  }

  addCliAsset('macOS Apple Silicon CLI', [
    /^nvpn-aarch64-apple-darwin\.tar\.gz$/,
    /^nvpn-v.*-aarch64-apple-darwin\.tar\.gz$/,
  ], [/^nvpn(?:-v.*)?-aarch64-apple-darwin\.tar\.gz$/])
  addCliAsset('Linux x64 CLI', [
    /^nvpn-x86_64-unknown-linux-musl\.tar\.gz$/,
    /^nvpn-v.*-x86_64-unknown-linux-musl\.tar\.gz$/,
  ], [/^nvpn(?:-v.*)?-x86_64-unknown-linux-musl\.tar\.gz$/])
  addCliAsset('Linux ARM64 CLI', [
    /^nvpn-aarch64-unknown-linux-musl\.tar\.gz$/,
    /^nvpn-v.*-aarch64-unknown-linux-musl\.tar\.gz$/,
  ], [/^nvpn(?:-v.*)?-aarch64-unknown-linux-musl\.tar\.gz$/])
  addCliAsset('Windows x64 CLI', [/^nvpn-v.*-x86_64-pc-windows-msvc\.zip$/])
  addCliAsset('Windows ARM64 CLI', [/^nvpn-v.*-aarch64-pc-windows-msvc\.zip$/])

  if (cliLines.length > 0) {
    lines.push('', '### Command Line', '', ...cliLines)
  }

  const otherLines = []
  for (const name of sortedNames) {
    if (usedAssets.has(name)) {
      continue
    }
    otherLines.push(`- ${describeAsset(name)}: ${assetReference(name, assetBaseUrl)}`)
  }

  if (otherLines.length > 0) {
    lines.push('', '### Other Files', '', ...otherLines)
  }
}

export function androidReleaseAssetName(tag, { extension = 'apk', signed = true } = {}) {
  const normalizedTag = normalizeTag(tag)
  const suffix = signed ? '' : '-unsigned'
  return `nostr-vpn-${normalizedTag}-android-arm64${suffix}.${extension}`
}

export function buildReleaseManifest({
  tag,
  commit,
  createdAt,
  assetPaths,
  draft = false,
  androidReleaseGate = null,
  releaseGateAttestation = null,
}) {
  const normalizedTag = normalizeTag(tag)
  const assets = [...assetPaths]
    .map((assetPath) => ({
      name: basename(assetPath),
      path: `assets/${basename(assetPath)}`,
      size: statSync(assetPath).size,
      sha256: sha256FileSync(assetPath),
    }))
    .sort((left, right) => left.name.localeCompare(right.name))

  const manifest = {
    id: normalizedTag,
    title: normalizedTag,
    tag: normalizedTag,
    commit,
    created_at: createdAt,
    published_at: createdAt,
    draft,
    prerelease: normalizedTag.includes('-'),
    notes_file: 'notes.md',
    assets,
  }
  if (androidReleaseGate) {
    manifest.android_release_gate = androidReleaseGate
  }
  if (releaseGateAttestation) {
    manifest.release_gate_attestation = releaseGateAttestation
  }
  return manifest
}

export function buildReleaseManifestFiles(manifest) {
  const text = `${JSON.stringify(manifest, null, 2)}\n`
  return [
    ['release.json', text],
    // Older desktop updater builds used manifest.json during
    // install even though checks read release.json. Keep both names identical
    // so old installed apps can update into a fixed build.
    ['manifest.json', text],
  ]
}

export function validateStagedReleaseTree(stageDir, manifest) {
  if (!manifest || !Array.isArray(manifest.assets)) {
    throw new Error('Release manifest does not contain an assets array.')
  }

  const seenNames = new Set()
  const seenPaths = new Set()
  for (const asset of manifest.assets) {
    if (!asset || typeof asset.path !== 'string' || typeof asset.name !== 'string') {
      throw new Error('Release manifest contains an asset without a name and path.')
    }
    if (seenNames.has(asset.name) || seenPaths.has(asset.path)) {
      throw new Error(`Release manifest contains a duplicate asset: ${asset.path}`)
    }
    seenNames.add(asset.name)
    seenPaths.add(asset.path)

    const normalizedPath = pathPosix.normalize(asset.path)
    if (
      normalizedPath !== asset.path ||
      normalizedPath.startsWith('..') ||
      normalizedPath.includes('/../') ||
      normalizedPath.startsWith('/') ||
      normalizedPath !== `assets/${asset.name}`
    ) {
      throw new Error(`Release manifest contains unsafe asset path: ${asset.path}`)
    }

    const assetPath = join(stageDir, normalizedPath)
    let stats
    try {
      stats = lstatSync(assetPath)
    } catch {
      throw new Error(`Release manifest lists missing asset: ${asset.path}`)
    }

    if (stats.isSymbolicLink() || !stats.isFile()) {
      throw new Error(
        `Release manifest asset is not a regular non-symlink file: ${asset.path}`,
      )
    }

    if (Number.isFinite(asset.size) && stats.size !== asset.size) {
      throw new Error(
        `Release manifest size mismatch for ${asset.path}: manifest ${asset.size} bytes, staged file ${stats.size} bytes.`,
      )
    }
    if (
      !/^[0-9a-f]{64}$/.test(String(asset.sha256 ?? ''))
      || sha256FileSync(assetPath) !== asset.sha256
    ) {
      throw new Error(`Release manifest SHA-256 mismatch for ${asset.path}.`)
    }
  }
}

export function renderReleaseNotes({
  tag,
  assetNames,
  changelogText = '',
  assetBaseUrl = '',
}) {
  const lines = []
  const changelogSection = extractChangelogSection(changelogText, tag)
  const productNotes = extractProductReleaseNotes(changelogSection, tag)

  if (productNotes) {
    lines.push(
      '## Reliability across every platform',
      '',
      ...productNotes.split('\n'),
      '',
    )
  }

  pushDownloadSections(lines, assetNames, assetBaseUrl)

  return `${lines.join('\n')}\n`
}
