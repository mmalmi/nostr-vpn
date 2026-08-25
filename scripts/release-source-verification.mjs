import { spawnSync } from 'node:child_process'
import {
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { basename, dirname, join, resolve } from 'node:path'
import process from 'node:process'
import { fileURLToPath } from 'node:url'

import {
  readWorkspaceVersionTag,
  semverFromTag,
  sha256FileSync,
} from './local-release-lib.mjs'
import { proveUnchangedPlatformInputs } from './release-component-source.mjs'

const scriptsDir = dirname(fileURLToPath(import.meta.url))
const defaultCandidateRoot = resolve(scriptsDir, '..')
const fipsPackageNames = [
  'nvpn-fips-core',
  'nvpn-fips-endpoint',
  'nvpn-fips-identity',
]
const cratesIoSource = 'registry+https://github.com/rust-lang/crates.io-index'

function requireRegularFile(path, label) {
  const metadata = lstatSync(path)
  if (metadata.isSymbolicLink() || !metadata.isFile()) {
    throw new Error(`${label} must be a regular non-symlink file.`)
  }
}

function captureRequired(command, args, { cwd, env, label }) {
  const result = spawnSync(command, args, {
    cwd,
    env,
    encoding: 'utf8',
    stdio: 'pipe',
    maxBuffer: 16 * 1024 * 1024,
  })
  if (result.status !== 0) {
    const stderr = String(result.stderr ?? '').trim()
    throw new Error(
      stderr ||
        result.error?.message ||
        `${label} failed with status ${result.status ?? 'unknown'}.`,
    )
  }
  const output = String(result.stdout ?? '').trim()
  if (!output) {
    throw new Error(`${label} produced no output.`)
  }
  return output
}

function runRequired(command, args, { cwd, env, label }) {
  const result = spawnSync(command, args, {
    cwd,
    env,
    encoding: 'utf8',
    stdio: 'pipe',
    maxBuffer: 16 * 1024 * 1024,
  })
  if (result.status !== 0) {
    const stderr = String(result.stderr ?? '').trim()
    throw new Error(
      stderr ||
        result.error?.message ||
        `${label} failed with status ${result.status ?? 'unknown'}.`,
    )
  }
}

export function withExactGitArchive({ root, commit, label, validate }) {
  const exactRoot = realpathSync(root)
  const temporaryRoot = mkdtempSync(join(tmpdir(), 'nvpn-exact-source-'))
  const archive = join(temporaryRoot, 'candidate.tar')
  const archiveRoot = join(temporaryRoot, 'candidate')
  mkdirSync(archiveRoot)
  try {
    runRequired(
      'git',
      ['archive', '--format=tar', `--output=${archive}`, commit],
      { cwd: exactRoot, env: process.env, label: `${label} archive` },
    )
    runRequired(
      'tar',
      ['-xf', archive, '-C', archiveRoot],
      { cwd: exactRoot, env: process.env, label: `${label} extraction` },
    )
    return validate(realpathSync(archiveRoot))
  } finally {
    rmSync(temporaryRoot, { recursive: true, force: true })
  }
}

function requireExactFields(receipt, expected, label) {
  if (!receipt || typeof receipt !== 'object' || Array.isArray(receipt)) {
    throw new Error(`${label} is missing.`)
  }
  for (const [field, value] of Object.entries(expected)) {
    if (receipt[field] !== value) {
      throw new Error(`${label} ${field} differs from the exact candidate.`)
    }
  }
}

function cargoLockRegistryPackage(lock, name, version) {
  const matches = lock
    .split(/^\[\[package\]\]\s*$/m)
    .slice(1)
    .filter((block) =>
      new RegExp(`^name = "${name}"$`, 'm').test(block)
      && new RegExp(`^version = "${version.replaceAll('.', '\\.')}"$`, 'm')
        .test(block),
    )
  if (matches.length !== 1) {
    throw new Error(
      `Cargo.lock must contain exactly one ${name} ${version} package.`,
    )
  }
  const source = matches[0].match(/^source = "([^"]+)"$/m)?.[1] ?? ''
  const checksum = matches[0].match(/^checksum = "([0-9a-f]{64})"$/m)?.[1] ?? ''
  if (source !== cratesIoSource || !/^[0-9a-f]{64}$/.test(checksum)) {
    throw new Error(
      `Cargo.lock does not bind ${name} ${version} to an exact crates.io checksum.`,
    )
  }
  return { source, checksum }
}

function cargoLockUniqueRegistryPackage(lock, name) {
  const matches = lock
    .split(/^\[\[package\]\]\s*$/m)
    .slice(1)
    .filter((block) => new RegExp(`^name = "${name}"$`, 'm').test(block))
  if (matches.length !== 1) {
    throw new Error(`Cargo.lock must contain exactly one ${name} package.`)
  }
  const version = matches[0].match(/^version = "([^"]+)"$/m)?.[1] ?? ''
  if (!/^[0-9]+\.[0-9]+\.[0-9]+(?:[+-][0-9A-Za-z.-]+)?$/.test(version)) {
    throw new Error(`Cargo.lock has an invalid ${name} version.`)
  }
  return { version, ...cargoLockRegistryPackage(lock, name, version) }
}

function requireFilePayload(receipt, name, expectedFile, label) {
  const payload = receipt?.payloads?.[name]
  if (
    payload?.file !== expectedFile
    || !/^[0-9a-f]{64}$/.test(String(payload?.sha256 ?? ''))
    || !Number.isSafeInteger(payload?.size)
    || payload.size <= 0
  ) {
    throw new Error(`${label} has an invalid ${name} payload.`)
  }
  return payload
}

export function createWindowsCratesIoSourceReceipt({
  appGitSha,
  appGitTree,
  fipsGitSha,
  fipsGitTree,
  fipsVersion,
  exactPackages,
}) {
  return {
    receiptSchema: 1,
    platform: 'windows',
    appGitSha,
    appGitTree,
    sourceClean: true,
    fipsReleaseGitSha: fipsGitSha,
    fipsReleaseGitTree: fipsGitTree,
    fipsReleaseTag: `v${fipsVersion}`,
    fipsVersion,
    fipsCrates: structuredClone(exactPackages),
  }
}

export function validateWindowsCratesIoReceipts({
  sourceReceipt,
  artifactReceipt,
  exactPackages,
  expectedAppGitSha,
  expectedAppGitTree,
  expectedFipsGitSha,
  expectedFipsGitTree,
  expectedFipsVersion,
}) {
  requireExactFields(
    sourceReceipt,
    {
      receiptSchema: 1,
      platform: 'windows',
      appGitSha: expectedAppGitSha,
      appGitTree: expectedAppGitTree,
      sourceClean: true,
      fipsReleaseGitSha: expectedFipsGitSha,
      fipsReleaseGitTree: expectedFipsGitTree,
      fipsReleaseTag: `v${expectedFipsVersion}`,
      fipsVersion: expectedFipsVersion,
    },
    'Windows exact crates.io source receipt',
  )
  if (
    JSON.stringify(sourceReceipt.fipsCrates)
    !== JSON.stringify(exactPackages)
  ) {
    throw new Error(
      'Windows exact crates.io source receipt package checksums/VCS differ from Cargo.',
    )
  }
  requireExactFields(
    artifactReceipt,
    {
      receiptSchema: 2,
      platform: 'windows',
      artifactType: 'exact installed Windows Release setup',
      appGitSha: expectedAppGitSha,
      appGitTree: expectedAppGitTree,
      fipsGitSha: expectedFipsGitSha,
      fipsGitTree: expectedFipsGitTree,
      fipsVersion: expectedFipsVersion,
      installerInstalledAndLaunched: true,
      installedAppStayedAlive: true,
      builtOnWindowsVm: true,
      builtOnHostMac: false,
    },
    'Windows exact installed-artifact receipt',
  )
  const payloadFiles = {
    app: 'NostrVpn.Windows.exe',
    appCore: 'nostr_vpn_app_core.dll',
    cli: 'nvpn.exe',
    wintun: 'binaries\\wintun.dll',
  }
  const payloadNames = Object.keys(payloadFiles)
  if (
    JSON.stringify(Object.keys(artifactReceipt.payloads ?? {}).sort())
    !== JSON.stringify([...payloadNames].sort())
  ) {
    throw new Error('Windows exact installed-artifact receipt has the wrong payload set.')
  }
  const payloads = Object.fromEntries(
    payloadNames.map((name) => [
      name,
      requireFilePayload(
        artifactReceipt,
        name,
        payloadFiles[name],
        'Windows exact installed-artifact receipt',
      ),
    ]),
  )
  return {
    expectedFipsVersion,
    cliSha256: payloads.cli.sha256,
    cliSize: payloads.cli.size,
    exactPackages,
  }
}

function resolveWindowsCratesIoFipsPackages({
  exactCandidateRoot,
  expectedFipsGitSha,
  expectedFipsVersion,
}) {
  const lock = readFileSync(join(exactCandidateRoot, 'Cargo.lock'), 'utf8')
  const metadata = JSON.parse(captureRequired(
    'cargo',
    ['metadata', '--locked', '--format-version', '1'],
    {
      cwd: exactCandidateRoot,
      env: { ...process.env, NVPN_FIPS_REPO_PATH: '' },
      label: 'Windows crates.io provenance metadata',
    },
  ))
  const expectedVersions = {
    'nvpn-fips-core': expectedFipsVersion,
    'nvpn-fips-endpoint': expectedFipsVersion,
    'nvpn-fips-identity': '0.3.3',
  }
  const exactPackages = {}
  for (const name of fipsPackageNames) {
    const version = expectedVersions[name]
    const matches = metadata.packages.filter(
      (item) => item.name === name && item.version === version,
    )
    if (matches.length !== 1 || matches[0].source !== cratesIoSource) {
      throw new Error(
        `Cargo metadata does not resolve exact crates.io ${name} ${version}.`,
      )
    }
    const lockPackage = cargoLockRegistryPackage(lock, name, version)
    const vcsPath = join(dirname(matches[0].manifest_path), '.cargo_vcs_info.json')
    requireRegularFile(vcsPath, `${name} crates.io VCS receipt`)
    let vcs
    try {
      vcs = JSON.parse(readFileSync(vcsPath, 'utf8'))
    } catch {
      throw new Error(`${name} crates.io VCS receipt is invalid.`)
    }
    const packageVcsSha = String(vcs?.git?.sha1 ?? '')
    const pathInVcs = String(vcs?.path_in_vcs ?? '')
    if (!/^[0-9a-f]{40}$/.test(packageVcsSha) || !pathInVcs) {
      throw new Error(`${name} crates.io VCS receipt is incomplete.`)
    }
    if (
      (name === 'nvpn-fips-core' || name === 'nvpn-fips-endpoint')
      && packageVcsSha !== expectedFipsGitSha
    ) {
      throw new Error(`${name} was not packaged from the exact FIPS release.`)
    }
    exactPackages[name] = {
      version,
      source: lockPackage.source,
      cargoLockChecksum: lockPackage.checksum,
      packageVcsSha,
      pathInVcs,
    }
  }
  return exactPackages
}

function resolveWindowsCratesIoFipsPackagesFromCommit({
  candidateRoot,
  expectedAppGitSha,
  expectedFipsGitSha,
  expectedFipsVersion,
}) {
  return withExactGitArchive({
    root: candidateRoot,
    commit: expectedAppGitSha,
    label: 'Windows crates.io provenance candidate',
    validate: (archiveRoot) => resolveWindowsCratesIoFipsPackages({
      exactCandidateRoot: archiveRoot,
      expectedFipsGitSha,
      expectedFipsVersion,
    }),
  })
}

export function createWindowsCratesIoSourceReceiptForCandidate({
  candidateRoot = defaultCandidateRoot,
  expectedAppGitSha,
  expectedAppGitTree,
  fipsRoot,
  expectedFipsGitSha,
  expectedFipsGitTree,
  expectedFipsVersion,
}) {
  const exactCandidateRoot = realpathSync(candidateRoot)
  const exactFipsRoot = realpathSync(fipsRoot)
  exactCleanGitCheckout({
    root: exactCandidateRoot,
    env: process.env,
    label: 'Windows crates.io source candidate',
    expectedCommit: expectedAppGitSha,
    expectedTree: expectedAppGitTree,
  })
  exactCleanGitCheckout({
    root: exactFipsRoot,
    env: process.env,
    label: 'Windows crates.io source FIPS',
    expectedCommit: expectedFipsGitSha,
    expectedTree: expectedFipsGitTree,
  })
  const exactPackages = resolveWindowsCratesIoFipsPackagesFromCommit({
    candidateRoot: exactCandidateRoot,
    expectedAppGitSha,
    expectedFipsGitSha,
    expectedFipsVersion,
  })
  exactCleanGitCheckout({
    root: exactCandidateRoot,
    env: process.env,
    label: 'Windows crates.io source candidate after source resolution',
    expectedCommit: expectedAppGitSha,
    expectedTree: expectedAppGitTree,
  })
  return createWindowsCratesIoSourceReceipt({
    appGitSha: expectedAppGitSha,
    appGitTree: expectedAppGitTree,
    fipsGitSha: expectedFipsGitSha,
    fipsGitTree: expectedFipsGitTree,
    fipsVersion: expectedFipsVersion,
    exactPackages,
  })
}

export function validateWindowsCratesIoFipsProvenance({
  sourceReceipt,
  artifactReceipt,
  candidateRoot = defaultCandidateRoot,
  expectedAppGitSha,
  expectedAppGitTree,
  fipsRoot,
  expectedFipsGitSha,
  expectedFipsGitTree,
  expectedFipsVersion,
}) {
  const exactCandidateRoot = realpathSync(candidateRoot)
  const exactFipsRoot = realpathSync(fipsRoot)
  const appTree = captureRequired(
    'git',
    ['rev-parse', `${expectedAppGitSha}^{tree}`],
    {
      cwd: exactCandidateRoot,
      env: process.env,
      label: 'Windows packaged app tree',
    },
  )
  if (appTree !== expectedAppGitTree) {
    throw new Error('Windows packaged app commit/tree differs from the receipt.')
  }
  exactCleanGitCheckout({
    root: exactFipsRoot,
    env: process.env,
    label: 'Windows crates.io provenance FIPS',
    expectedCommit: expectedFipsGitSha,
    expectedTree: expectedFipsGitTree,
  })

  const exactPackages = resolveWindowsCratesIoFipsPackagesFromCommit({
    candidateRoot: exactCandidateRoot,
    expectedAppGitSha,
    expectedFipsGitSha,
    expectedFipsVersion,
  })

  return validateWindowsCratesIoReceipts({
    sourceReceipt,
    artifactReceipt,
    exactPackages,
    expectedAppGitSha,
    expectedAppGitTree,
    expectedFipsGitSha,
    expectedFipsGitTree,
    expectedFipsVersion,
  })
}

function exactCleanGitCheckout({
  root,
  env,
  label,
  expectedCommit = '',
  expectedTree = '',
}) {
  const commit = captureRequired('git', ['rev-parse', 'HEAD'], {
    cwd: root,
    env,
    label: `${label} commit`,
  })
  const tree = captureRequired('git', ['rev-parse', 'HEAD^{tree}'], {
    cwd: root,
    env,
    label: `${label} tree`,
  })
  const status = spawnSync(
    'git',
    ['status', '--porcelain=v1', '--untracked-files=all'],
    {
      cwd: root,
      env,
      encoding: 'utf8',
      stdio: 'pipe',
    },
  )
  if (
    status.status !== 0 ||
    String(status.stdout ?? '').trim() ||
    (expectedCommit && commit !== expectedCommit) ||
    (expectedTree && tree !== expectedTree)
  ) {
    throw new Error(
      `${label} checkout is dirty or differs from the exact candidate.`,
    )
  }
  return { commit, tree }
}

export function exactFipsPublicationCandidate({
  env,
  candidateRoot = defaultCandidateRoot,
  label = 'Release publication',
}) {
  const exactCandidateRoot = realpathSync(candidateRoot)
  const expectedFipsGitSha = String(
    env?.NVPN_EXPECTED_FIPS_GIT_SHA ?? '',
  ).trim()
  if (!/^[0-9a-f]{40}$/.test(expectedFipsGitSha)) {
    throw new Error(
      `${label} requires an exact lowercase NVPN_EXPECTED_FIPS_GIT_SHA.`,
    )
  }
  const expectedFipsGitTree = String(
    env?.NVPN_EXPECTED_FIPS_GIT_TREE ?? '',
  ).trim()
  if (!/^[0-9a-f]{40}$/.test(expectedFipsGitTree)) {
    throw new Error(
      `${label} requires an exact lowercase NVPN_EXPECTED_FIPS_GIT_TREE.`,
    )
  }
  const expectedFipsVersion = String(
    env?.NVPN_EXPECTED_FIPS_VERSION ?? '',
  ).trim()
  if (!/^[0-9]+\.[0-9]+\.[0-9]+(?:[+-][0-9A-Za-z.-]+)?$/.test(
    expectedFipsVersion,
  )) {
    throw new Error(
      `${label} requires an exact NVPN_EXPECTED_FIPS_VERSION.`,
    )
  }

  const lockVerifierPath = join(
    exactCandidateRoot,
    'scripts',
    'verify-cargo-path-patch-lock.py',
  )
  requireRegularFile(lockVerifierPath, `${label} exact FIPS lock verifier`)
  const rootCargoLockPath = join(exactCandidateRoot, 'Cargo.lock')
  requireRegularFile(rootCargoLockPath, `${label} exact Cargo lock`)
  const lock = readFileSync(rootCargoLockPath, 'utf8')
  cargoLockRegistryPackage(lock, 'nvpn-fips-core', expectedFipsVersion)
  cargoLockRegistryPackage(lock, 'nvpn-fips-endpoint', expectedFipsVersion)
  const identity = cargoLockUniqueRegistryPackage(lock, 'nvpn-fips-identity')
  const packageVersions = {
    'nvpn-fips-core': expectedFipsVersion,
    'nvpn-fips-endpoint': expectedFipsVersion,
    'nvpn-fips-identity': identity.version,
  }

  return {
    fipsGitSha: expectedFipsGitSha,
    fipsGitTree: expectedFipsGitTree,
    fipsVersion: expectedFipsVersion,
    fipsSpecifications: fipsPackageNames.map(
      (name) => `${name}=${packageVersions[name]}`,
    ),
    fipsPatchedLockPackages: packageVersions,
    lockVerifierPath,
  }
}

export function validateWindowsPublicationFipsReceipts({
  artifactReceipt,
  installerReceipt,
  expectedFips,
}) {
  const expected = {
    fipsGitSha: expectedFips?.fipsGitSha,
    fipsGitTree: expectedFips?.fipsGitTree,
    fipsVersion: expectedFips?.fipsVersion,
  }
  if (
    !/^[0-9a-f]{40}$/.test(String(expected.fipsGitSha ?? '')) ||
    !/^[0-9a-f]{40}$/.test(String(expected.fipsGitTree ?? '')) ||
    !/^[0-9]+\.[0-9]+\.[0-9]+(?:[+-][0-9A-Za-z.-]+)?$/.test(
      String(expected.fipsVersion ?? ''),
    )
  ) {
    throw new Error(
      'Windows publication exact candidate FIPS identity is invalid.',
    )
  }
  requireExactFields(
    artifactReceipt,
    expected,
    'Windows exact-artifact gate receipt',
  )
  requireExactFields(
    installerReceipt,
    expected,
    'Windows exact installer gate receipt',
  )
  return expected
}

export function linuxPublicationVerificationPlan({
  env,
  tag,
  candidateCommit,
  candidateTree,
  gateReceipt,
  packageInstallReceipt,
  bundlePath,
  bundleReceiptPath,
  bundleReceiptSha256,
  candidateRoot = defaultCandidateRoot,
  hostPlatform = process.platform,
  hostArch = process.arch,
}) {
  const builderMode = String(env?.NVPN_HOST_LINUX_VM_BUILDER_MODE ?? '').trim()
  if (!builderMode) {
    throw new Error(
      'Linux publication requires an explicit builder mode via NVPN_HOST_LINUX_VM_BUILDER_MODE.',
    )
  }
  if (!['local-docker', 'remote-native'].includes(builderMode)) {
    throw new Error(
      `Linux publication builder mode is unsupported: ${builderMode}`,
    )
  }
  if (
    builderMode === 'local-docker' &&
    hostPlatform === 'darwin' &&
    hostArch === 'arm64'
  ) {
    throw new Error(
      'Darwin arm64 Linux publication requires remote-native builder mode; local QEMU artifacts are not accepted.',
    )
  }
  if (
    builderMode === 'local-docker' &&
    (hostPlatform !== 'darwin' || hostArch !== 'x64')
  ) {
    throw new Error(
      'local-docker Linux publication requires a native x86_64 Darwin host.',
    )
  }
  if (
    builderMode === 'remote-native' &&
    !String(env?.NVPN_HOST_LINUX_VM_NATIVE_BUILDER_HOST ?? '').trim()
  ) {
    throw new Error(
      'remote-native Linux publication requires an explicit native builder host.',
    )
  }

  const exactCandidateRoot = realpathSync(candidateRoot)
  const commandEnv = { ...process.env, ...env }
  const candidateGit = exactCleanGitCheckout({
    root: exactCandidateRoot,
    env: commandEnv,
    label: 'Linux publication worktree',
    expectedCommit: candidateCommit,
    expectedTree: candidateTree,
  })
  const actualCommit = candidateGit.commit
  const actualTree = candidateGit.tree
  const artifactCommit = String(gateReceipt?.appGitSha ?? '')
  const artifactTree = String(gateReceipt?.appGitTree ?? '')
  if (artifactCommit !== actualCommit || artifactTree !== actualTree) {
    proveUnchangedPlatformInputs({
      candidateRoot: exactCandidateRoot,
      platform: 'linux',
      receiptCommit: artifactCommit,
      receiptTree: artifactTree,
      candidateCommit: actualCommit,
      candidateTree: actualTree,
    })
  }

  const rootManifestPath = join(exactCandidateRoot, 'Cargo.toml')
  requireRegularFile(rootManifestPath, 'Linux publication workspace manifest')
  const workspaceVersion = semverFromTag(
    readWorkspaceVersionTag(readFileSync(rootManifestPath, 'utf8')),
  )
  const appVersion = semverFromTag(tag)
  if (workspaceVersion !== appVersion) {
    throw new Error(
      'Linux publication tag differs from the exact workspace version.',
    )
  }

  const fips = exactFipsPublicationCandidate({
    env,
    candidateRoot: exactCandidateRoot,
    label: 'Linux publication',
  })
  const rootCargoLockPath = join(exactCandidateRoot, 'Cargo.lock')
  const linuxCargoLockPath = join(exactCandidateRoot, 'linux', 'Cargo.lock')
  requireRegularFile(rootCargoLockPath, 'Linux publication root Cargo lock')
  requireRegularFile(linuxCargoLockPath, 'Linux publication desktop Cargo lock')
  const rootCargoLockSha256 = sha256FileSync(rootCargoLockPath)
  const linuxCargoLockSha256 = sha256FileSync(linuxCargoLockPath)
  const realizedLock = (path, label) =>
    captureRequired(
      'python3',
      [
        fips.lockVerifierPath,
        '--expected-sha256',
        path,
        ...fips.fipsSpecifications,
      ],
      {
        cwd: exactCandidateRoot,
        env: commandEnv,
        label,
      },
    )
  const rootRealizedCargoLockSha256 = realizedLock(
    rootCargoLockPath,
    'Linux publication realized root Cargo lock',
  )
  const linuxRealizedCargoLockSha256 = realizedLock(
    linuxCargoLockPath,
    'Linux publication realized desktop Cargo lock',
  )
  for (const [label, value] of Object.entries({
    rootCargoLockSha256,
    rootRealizedCargoLockSha256,
    linuxCargoLockSha256,
    linuxRealizedCargoLockSha256,
  })) {
    if (!/^[0-9a-f]{64}$/.test(value)) {
      throw new Error(`Linux publication ${label} is invalid.`)
    }
  }

  const rustToolchain = String(
    env?.NVPN_HOST_LINUX_VM_RUST_TOOLCHAIN || '1.95.0',
  ).trim()
  if (!/^[0-9]+\.[0-9]+\.[0-9]+$/.test(rustToolchain)) {
    throw new Error(
      'Linux publication Rust toolchain must be an exact stable version.',
    )
  }
  const dockerfilePath = join(exactCandidateRoot, 'Dockerfile.linux-vm-gate')
  const containerPayloadPath = join(
    exactCandidateRoot,
    'scripts',
    'build-host-linux-vm-bundle-in-container.sh',
  )
  requireRegularFile(dockerfilePath, 'Linux publication Dockerfile')
  requireRegularFile(
    containerPayloadPath,
    'Linux publication container payload',
  )
  const dockerfileSha256 = sha256FileSync(dockerfilePath)
  const containerPayloadSha256 = sha256FileSync(containerPayloadPath)
  const sourceDateEpoch = Number(
    captureRequired('git', ['log', '-1', '--format=%ct', artifactCommit], {
      cwd: exactCandidateRoot,
      env: commandEnv,
      label: 'Linux publication source date epoch',
    }),
  )
  if (!Number.isSafeInteger(sourceDateEpoch) || sourceDateEpoch <= 0) {
    throw new Error(
      'Linux publication candidate has an invalid source date epoch.',
    )
  }

  const target = 'x86_64-unknown-linux-gnu'
  const expectedBuilder =
    builderMode === 'remote-native'
      ? {
          builtOnHostMac: false,
          builtOnRemoteVm: true,
          builderHostOs: 'Linux',
          builderHostArchitecture: 'x86_64',
        }
      : {
          builtOnHostMac: true,
          builtOnRemoteVm: false,
          builderHostOs: 'Darwin',
          builderHostArchitecture: 'x86_64',
        }
  requireExactFields(
    gateReceipt,
    {
      schema: 2,
      builderMode,
      ...expectedBuilder,
      appGitSha: artifactCommit,
      appGitTree: artifactTree,
      appVersion,
      fipsGitSha: fips.fipsGitSha,
      fipsGitTree: fips.fipsGitTree,
      fipsVersion: fips.fipsVersion,
      rootCargoLockSha256,
      rootRealizedCargoLockSha256,
      linuxCargoLockSha256,
      linuxRealizedCargoLockSha256,
      target,
      dockerPlatform: 'linux/amd64',
      containerBase: 'ubuntu:24.04',
      dockerfileSha256,
      containerPayloadSha256,
      sourceDateEpoch,
    },
    'Linux exact-artifact gate receipt',
  )
  const receiptFipsPackages = gateReceipt.fipsPatchedLockPackages
  if (
    !receiptFipsPackages ||
    typeof receiptFipsPackages !== 'object' ||
    Array.isArray(receiptFipsPackages) ||
    Object.keys(receiptFipsPackages).length !== fipsPackageNames.length ||
    fipsPackageNames.some(
      (name) =>
        receiptFipsPackages[name] !== fips.fipsPatchedLockPackages[name],
    )
  ) {
    throw new Error(
      'Linux exact-artifact gate receipt fipsPatchedLockPackages differs from the exact candidate.',
    )
  }
  if (
    !/^sha256:[0-9a-f]{64}$/.test(String(gateReceipt.containerImageId ?? '')) ||
    !String(gateReceipt.rustcVersion ?? '').startsWith(
      `rustc ${rustToolchain} `,
    ) ||
    !String(gateReceipt.cargoVersion ?? '').startsWith(
      `cargo ${rustToolchain} `,
    )
  ) {
    throw new Error(
      'Linux exact-artifact gate receipt has the wrong container or Rust toolchain.',
    )
  }

  const exactBundleReceiptSha256 = String(bundleReceiptSha256 ?? '').trim()
  if (!/^[0-9a-f]{64}$/.test(exactBundleReceiptSha256)) {
    throw new Error('Linux exact host-bundle receipt SHA-256 is invalid.')
  }
  requireExactFields(
    packageInstallReceipt,
    {
      schema: 2,
      artifactType: 'exact Debian package installed on Ubuntu VM',
      appGitSha: artifactCommit,
      appGitTree: artifactTree,
      fipsGitSha: fips.fipsGitSha,
      fipsGitTree: fips.fipsGitTree,
      appVersion,
      builderMode,
      ...expectedBuilder,
      containerImageId: gateReceipt.containerImageId,
      dockerfileSha256,
      containerPayloadSha256,
      bundleReceiptSha256: exactBundleReceiptSha256,
    },
    'Linux exact Debian package install receipt',
  )

  const exactBundlePath = realpathSync(bundlePath)
  const exactBundleReceiptPath = realpathSync(bundleReceiptPath)
  if (
    dirname(exactBundleReceiptPath) !== exactBundlePath ||
    basename(exactBundleReceiptPath) !== 'receipt.json'
  ) {
    throw new Error(
      'Linux exact host-bundle receipt is not inside the exact bundle.',
    )
  }
  const verifierPath = join(
    exactCandidateRoot,
    'scripts',
    'verify-host-linux-vm-bundle.py',
  )
  requireRegularFile(verifierPath, 'Linux exact host-bundle verifier')
  exactCleanGitCheckout({
    root: exactCandidateRoot,
    env: commandEnv,
    label: 'Linux publication worktree',
    expectedCommit: actualCommit,
    expectedTree: actualTree,
  })
  return {
    candidateRoot: exactCandidateRoot,
    verifierPath,
    verifierArgs: [
      exactBundlePath,
      exactBundleReceiptPath,
      artifactCommit,
      artifactTree,
      appVersion,
      fips.fipsGitSha,
      fips.fipsGitTree,
      fips.fipsVersion,
      rootCargoLockSha256,
      rootRealizedCargoLockSha256,
      linuxCargoLockSha256,
      linuxRealizedCargoLockSha256,
      target,
      builderMode,
      rustToolchain,
      dockerfileSha256,
      containerPayloadSha256,
      ...fips.fipsSpecifications,
    ],
  }
}

if (
  process.argv[1]
  && realpathSync(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  const command = process.argv[2]
  if (command === 'windows-cratesio-source-receipt') {
    const [
      expectedAppGitSha,
      expectedAppGitTree,
      fipsRoot,
      expectedFipsGitSha,
      expectedFipsGitTree,
      expectedFipsVersion,
    ] = process.argv.slice(3)
    if (
      !expectedAppGitSha
      || !expectedAppGitTree
      || !fipsRoot
      || !expectedFipsGitSha
      || !expectedFipsGitTree
      || !expectedFipsVersion
    ) {
      throw new Error(
        'Usage: release-source-verification.mjs windows-cratesio-source-receipt ' +
        '<app-sha> <app-tree> <fips-root> <fips-sha> <fips-tree> <fips-version>',
      )
    }
    const receipt = createWindowsCratesIoSourceReceiptForCandidate({
      expectedAppGitSha,
      expectedAppGitTree,
      fipsRoot,
      expectedFipsGitSha,
      expectedFipsGitTree,
      expectedFipsVersion,
    })
    process.stdout.write(`${JSON.stringify(receipt, null, 2)}\n`)
    process.exit(0)
  }
  const [
    provenanceCommand,
    sourceReceiptPath,
    artifactReceiptPath,
    expectedAppGitSha,
    expectedAppGitTree,
    fipsRoot,
    expectedFipsGitSha,
    expectedFipsGitTree,
    expectedFipsVersion,
  ] = process.argv.slice(2)
  if (
    provenanceCommand !== 'windows-cratesio-provenance'
    || !sourceReceiptPath
    || !artifactReceiptPath
    || !expectedAppGitSha
    || !expectedAppGitTree
    || !fipsRoot
    || !expectedFipsGitSha
    || !expectedFipsGitTree
    || !expectedFipsVersion
  ) {
    throw new Error(
      'Usage: release-source-verification.mjs windows-cratesio-provenance ' +
      '<source-receipt> <artifact-receipt> <app-sha> <app-tree> ' +
      '<fips-root> <fips-sha> <fips-tree> <fips-version>',
    )
  }
  const result = validateWindowsCratesIoFipsProvenance({
    sourceReceipt: JSON.parse(
      readFileSync(sourceReceiptPath, 'utf8').replace(/^\uFEFF/, ''),
    ),
    artifactReceipt: JSON.parse(
      readFileSync(artifactReceiptPath, 'utf8').replace(/^\uFEFF/, ''),
    ),
    expectedAppGitSha,
    expectedAppGitTree,
    fipsRoot,
    expectedFipsGitSha,
    expectedFipsGitTree,
    expectedFipsVersion,
  })
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`)
}
