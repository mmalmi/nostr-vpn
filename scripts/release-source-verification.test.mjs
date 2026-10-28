import test from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import {
  copyFileSync,
  mkdtempSync,
  mkdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'

import {
  createWindowsCratesIoSourceReceipt,
  exactFipsPublicationCandidate,
  linuxPublicationVerificationPlan,
  withExactGitArchive,
  validateWindowsCratesIoReceipts,
  validateWindowsRuntimeFipsVersion,
  validateMacosRuntimeFipsVersion,
  validateWindowsPublicationFipsReceipts,
} from './release-source-verification.mjs'
import { readWorkspaceVersionTag } from './local-release-lib.mjs'

const workspaceTag = readWorkspaceVersionTag(
  readFileSync(join(process.cwd(), 'Cargo.toml'), 'utf8'),
)
const workspaceVersion = workspaceTag.slice(1)

function exactWindowsCratesIoFixture() {
  const appGitSha = 'a'.repeat(40)
  const appGitTree = 'b'.repeat(40)
  const fipsGitSha = 'c'.repeat(40)
  const fipsGitTree = 'd'.repeat(40)
  const exactPackages = {
    'nvpn-fips-core': {
      version: '0.4.53',
      source: 'registry+https://github.com/rust-lang/crates.io-index',
      cargoLockChecksum: '1'.repeat(64),
      packageVcsSha: fipsGitSha,
      pathInVcs: 'crates/fips-core',
    },
    'nvpn-fips-endpoint': {
      version: '0.4.53',
      source: 'registry+https://github.com/rust-lang/crates.io-index',
      cargoLockChecksum: '2'.repeat(64),
      packageVcsSha: fipsGitSha,
      pathInVcs: 'crates/fips-endpoint',
    },
    'nvpn-fips-identity': {
      version: '0.3.3',
      source: 'registry+https://github.com/rust-lang/crates.io-index',
      cargoLockChecksum: '3'.repeat(64),
      packageVcsSha: 'e'.repeat(40),
      pathInVcs: 'crates/fips-identity',
    },
  }
  const sourceReceipt = {
    receiptSchema: 1,
    platform: 'windows',
    appGitSha,
    appGitTree,
    sourceClean: true,
    fipsReleaseGitSha: fipsGitSha,
    fipsReleaseGitTree: fipsGitTree,
    fipsReleaseTag: 'v0.4.53',
    fipsVersion: '0.4.53',
    fipsCrates: structuredClone(exactPackages),
  }
  const payloadFiles = {
    app: 'NostrVpn.Windows.exe',
    appCore: 'nostr_vpn_app_core.dll',
    cli: 'nvpn.exe',
    wintun: 'binaries\\wintun.dll',
  }
  const payloads = Object.fromEntries(
    Object.entries(payloadFiles).map(([name, file], index) => [
      name,
      { file, sha256: String(index + 4).repeat(64), size: index + 1 },
    ]),
  )
  const artifactReceipt = {
    receiptSchema: 2,
    platform: 'windows',
    artifactType: 'exact installed Windows Release setup',
    appGitSha,
    appGitTree,
    fipsGitSha,
    fipsGitTree,
    fipsVersion: '0.4.53',
    installerInstalledAndLaunched: true,
    installedAppStayedAlive: true,
    builtOnWindowsVm: true,
    builtOnHostMac: false,
    payloads,
  }
  return {
    sourceReceipt,
    artifactReceipt,
    exactPackages,
    expectedAppGitSha: appGitSha,
    expectedAppGitTree: appGitTree,
    expectedFipsGitSha: fipsGitSha,
    expectedFipsGitTree: fipsGitTree,
    expectedFipsVersion: '0.4.53',
  }
}

test('Windows crates.io source receipt records the exact candidate inputs', () => {
  const fixture = exactWindowsCratesIoFixture()
  assert.deepEqual(
    createWindowsCratesIoSourceReceipt({
      appGitSha: fixture.expectedAppGitSha,
      appGitTree: fixture.expectedAppGitTree,
      fipsGitSha: fixture.expectedFipsGitSha,
      fipsGitTree: fixture.expectedFipsGitTree,
      fipsVersion: fixture.expectedFipsVersion,
      exactPackages: fixture.exactPackages,
    }),
    fixture.sourceReceipt,
  )
})

test('Windows crates.io receipts accept the exact sealed source and payloads', () => {
  const fixture = exactWindowsCratesIoFixture()
  assert.deepEqual(validateWindowsCratesIoReceipts(fixture), {
    expectedFipsVersion: '0.4.53',
    cliSha256: '6'.repeat(64),
    cliSize: 3,
    exactPackages: fixture.exactPackages,
  })
})

test('Windows crates.io receipts reject source, VCS, and artifact drift', () => {
  for (const [label, mutate, error] of [
    [
      'lock checksum',
      (fixture) => { fixture.sourceReceipt.fipsCrates['nvpn-fips-core'].cargoLockChecksum = '9'.repeat(64) },
      /package checksums\/VCS differ/,
    ],
    [
      'package VCS',
      (fixture) => { fixture.sourceReceipt.fipsCrates['nvpn-fips-core'].packageVcsSha = '9'.repeat(40) },
      /package checksums\/VCS differ/,
    ],
    [
      'registry source',
      (fixture) => { fixture.sourceReceipt.fipsCrates['nvpn-fips-core'].source = 'path+file:///tmp/fips' },
      /package checksums\/VCS differ/,
    ],
    [
      'package set',
      (fixture) => { delete fixture.sourceReceipt.fipsCrates['nvpn-fips-identity'] },
      /package checksums\/VCS differ/,
    ],
    [
      'artifact FIPS SHA',
      (fixture) => { fixture.artifactReceipt.fipsGitSha = '9'.repeat(40) },
      /fipsGitSha differs/,
    ],
    [
      'artifact version',
      (fixture) => { fixture.artifactReceipt.fipsVersion = '0.4.49' },
      /fipsVersion differs/,
    ],
    [
      'invalid CLI payload',
      (fixture) => { fixture.artifactReceipt.payloads.cli.sha256 = 'nope' },
      /invalid cli payload/,
    ],
    [
      'mislabeled app-core payload',
      (fixture) => { fixture.artifactReceipt.payloads.appCore.file = 'NostrVpn.Windows.dll' },
      /invalid appCore payload/,
    ],
    [
      'not installed',
      (fixture) => { fixture.artifactReceipt.installerInstalledAndLaunched = false },
      /installerInstalledAndLaunched differs/,
    ],
  ]) {
    const fixture = exactWindowsCratesIoFixture()
    mutate(fixture)
    assert.throws(
      () => validateWindowsCratesIoReceipts(fixture),
      error,
      label,
    )
  }
})

function capture(command, args, cwd) {
  const result = spawnSync(command, args, {
    cwd,
    encoding: 'utf8',
    stdio: 'pipe',
  })
  assert.equal(
    result.status,
    0,
    result.stderr || `${command} failed with ${result.status}`,
  )
  return result.stdout.trim()
}

test('exact Git archive validation ignores a later dirty Cargo.lock', (context) => {
  const root = mkdtempSync(join(tmpdir(), 'nvpn-exact-git-archive-'))
  context.after(() => rmSync(root, { recursive: true, force: true }))
  const lock = join(root, 'Cargo.lock')
  writeFileSync(lock, 'sealed registry lock\n')
  capture('git', ['init', '--quiet'], root)
  capture('git', ['add', 'Cargo.lock'], root)
  capture(
    'git',
    [
      '-c',
      'user.name=Release Test',
      '-c',
      'user.email=release-test@example.invalid',
      'commit',
      '--quiet',
      '-m',
      'sealed source',
    ],
    root,
  )
  const commit = capture('git', ['rev-parse', 'HEAD'], root)
  writeFileSync(lock, 'temporary local path lock\n')

  assert.equal(
    withExactGitArchive({
      root,
      commit,
      label: 'Windows source fixture',
      validate: (archiveRoot) =>
        readFileSync(join(archiveRoot, 'Cargo.lock'), 'utf8'),
    }),
    'sealed registry lock\n',
  )
  assert.equal(readFileSync(lock, 'utf8'), 'temporary local path lock\n')
})

test('Windows final provenance resolves packages from the sealed commit', () => {
  const source = readFileSync(
    join(process.cwd(), 'scripts', 'release-source-verification.mjs'),
    'utf8',
  )
  const body = source
    .split('export function validateWindowsCratesIoFipsProvenance({')[1]
    .split('\nexport function ')[0]
  assert.match(body, /resolveWindowsCratesIoFipsPackagesFromCommit\(\{/)
  assert.doesNotMatch(
    body,
    /resolveWindowsCratesIoFipsPackages\(\{\s*exactCandidateRoot,/,
  )
})

test('Windows crates.io provenance bypasses the release-gate path patch', () => {
  const verifier = readFileSync(
    join(process.cwd(), 'scripts', 'release-source-verification.mjs'),
    'utf8',
  )
  const resolver = verifier
    .split('function resolveWindowsCratesIoFipsPackages({')[1]
    .split('\nfunction resolveWindowsCratesIoFipsPackagesFromCommit')[0]
  assert.match(
    resolver,
    /NVPN_FIPS_REPO_PATH:\s*''/,
    'the crates.io resolver must explicitly disable local FIPS',
  )

  const gate = readFileSync(
    join(process.cwd(), 'scripts', 'release-gate.sh'),
    'utf8',
  )
  const wrapper = gate
    .split('install_release_cargo_wrapper() {')[1]
    .split('\n}\n\ntoml_string()')[0]
  assert.match(
    wrapper,
    /NVPN_FIPS_REPO_PATH.*exec.*real_cargo/s,
    'the gate Cargo wrapper must honor the resolver\'s crates.io mode',
  )
})

function sha256(path) {
  return createHash('sha256').update(readFileSync(path)).digest('hex')
}

function committedRegistryPackageVersion(name) {
  const lock = trackedFixtureInput(process.cwd(), 'Cargo.lock').toString('utf8')
  const versions = lock
    .split(/\n(?=\[\[package\]\]\n)/)
    .filter((block) =>
      block.includes(`name = "${name}"`) &&
      block.includes('source = "registry+'),
    )
    .map((block) => block.match(/^version = "([^"]+)"$/m)?.[1])
    .filter(Boolean)
  assert.equal(
    versions.length,
    1,
    `committed Cargo.lock must contain exactly one registry ${name} package`,
  )
  return versions[0]
}

const fipsPackages = Object.fromEntries(
  [
    'nvpn-fips-core',
    'nvpn-fips-endpoint',
    'nvpn-fips-identity',
    'nvpn-mdns-sd',
    'nvpn-turn',
    'nvpn-webrtc',
    'nvpn-webrtc-ice',
    'nvpn-webrtc-util',
    'nvpn-dtls',
  ].map((name) => [
    name,
    committedRegistryPackageVersion(name),
  ]),
)
const fipsSpecs = Object.entries(fipsPackages).map(
  ([name, version]) => `${name}=${version}`,
)
const committedLockPaths = new Set(['Cargo.lock', 'linux/Cargo.lock'])

function trackedFixtureInput(sourceRoot, relative) {
  const result = spawnSync('git', ['show', `HEAD:${relative}`], {
    cwd: sourceRoot,
    stdio: ['ignore', 'pipe', 'pipe'],
  })
  assert.equal(
    result.status,
    0,
    result.stderr.toString() || `could not read tracked ${relative}`,
  )
  return result.stdout
}

function copyFixtureInput(sourceRoot, relative, destination) {
  // A release-gate local-FIPS session may legitimately realize Cargo.lock in
  // place. Locks model committed source, while all other inputs intentionally
  // exercise current TDD edits and retain their copied file modes.
  if (committedLockPaths.has(relative)) {
    writeFileSync(destination, trackedFixtureInput(sourceRoot, relative))
    return
  }
  copyFileSync(join(sourceRoot, relative), destination)
}

test('publication fixture reads committed lock while the worktree uses exact local FIPS', (context) => {
  const sourceRoot = mkdtempSync(
    join(tmpdir(), 'nvpn-publication-source-lock-'),
  )
  context.after(() => rmSync(sourceRoot, { recursive: true, force: true }))
  const committedLock = trackedFixtureInput(process.cwd(), 'Cargo.lock')
  const sourceLock = join(sourceRoot, 'Cargo.lock')
  writeFileSync(sourceLock, committedLock)
  capture('git', ['init', '--quiet'], sourceRoot)
  capture('git', ['add', 'Cargo.lock'], sourceRoot)
  capture(
    'git',
    [
      '-c',
      'user.name=Release Test',
      '-c',
      'user.email=release-test@example.invalid',
      'commit',
      '--quiet',
      '-m',
      'committed lock fixture',
    ],
    sourceRoot,
  )
  const realizedLock = join(sourceRoot, 'Cargo.realized.lock')
  capture(
    'python3',
    [
      join(process.cwd(), 'scripts', 'verify-cargo-path-patch-lock.py'),
      '--materialize',
      sourceLock,
      realizedLock,
      ...fipsSpecs,
    ],
    sourceRoot,
  )
  copyFileSync(realizedLock, sourceLock)
  assert.equal(capture('git', ['diff', '--name-only'], sourceRoot), 'Cargo.lock')
  assert.notDeepEqual(readFileSync(sourceLock), committedLock)

  const copiedLock = join(sourceRoot, 'fixture-Cargo.lock')
  copyFixtureInput(sourceRoot, 'Cargo.lock', copiedLock)
  assert.deepEqual(readFileSync(copiedLock), committedLock)
})

test('Linux publication derives verifier inputs and rejects self-consistent receipt forgeries', (context) => {
  const sourceRoot = process.cwd()
  const temporaryRoot = mkdtempSync(
    join(tmpdir(), 'nvpn-linux-publication-verifier-'),
  )
  context.after(() => rmSync(temporaryRoot, { recursive: true, force: true }))

  const root = join(temporaryRoot, 'candidate')
  for (const relative of [
    'Cargo.toml',
    'Cargo.lock',
    'linux/Cargo.lock',
    'Dockerfile.linux-vm-gate',
    'scripts/build-host-linux-vm-bundle-in-container.sh',
    'scripts/verify-cargo-path-patch-lock.py',
    'scripts/verify-host-linux-vm-bundle.py',
  ]) {
    const destination = join(root, relative)
    mkdirSync(dirname(destination), { recursive: true })
    copyFixtureInput(sourceRoot, relative, destination)
  }
  capture('git', ['init', '--quiet'], root)
  capture('git', ['add', '.'], root)
  capture(
    'git',
    [
      '-c',
      'user.name=Release Test',
      '-c',
      'user.email=release-test@example.invalid',
      'commit',
      '--quiet',
      '-m',
      'candidate fixture',
    ],
    root,
  )

  const fipsRoot = join(temporaryRoot, 'fips')
  for (const [name, version] of Object.entries(fipsPackages)) {
    const crate = join(fipsRoot, 'crates', name)
    mkdirSync(crate, { recursive: true })
    writeFileSync(
      join(crate, 'Cargo.toml'),
      `[package]\nname = "${name}"\nversion = "${version}"\n`,
    )
  }
  capture('git', ['init', '--quiet'], fipsRoot)
  capture('git', ['add', '.'], fipsRoot)
  capture(
    'git',
    [
      '-c',
      'user.name=Release Test',
      '-c',
      'user.email=release-test@example.invalid',
      'commit',
      '--quiet',
      '-m',
      'fixture',
    ],
    fipsRoot,
  )

  const candidateCommit = capture('git', ['rev-parse', 'HEAD'], root)
  const candidateTree = capture('git', ['rev-parse', 'HEAD^{tree}'], root)
  const fipsGitSha = capture('git', ['rev-parse', 'HEAD'], fipsRoot)
  const fipsGitTree = capture('git', ['rev-parse', 'HEAD^{tree}'], fipsRoot)
  const sourceDateEpoch = Number(
    capture('git', ['log', '-1', '--format=%ct', candidateCommit], root),
  )
  const lockVerifier = join(root, 'scripts', 'verify-cargo-path-patch-lock.py')
  const rootLock = join(root, 'Cargo.lock')
  const linuxLock = join(root, 'linux', 'Cargo.lock')
  const rootRealizedCargoLockSha256 = capture(
    'python3',
    [lockVerifier, '--expected-sha256', rootLock, ...fipsSpecs],
    root,
  )
  const linuxRealizedCargoLockSha256 = capture(
    'python3',
    [lockVerifier, '--expected-sha256', linuxLock, ...fipsSpecs],
    root,
  )
  const bundlePath = join(temporaryRoot, 'bundle')
  mkdirSync(bundlePath)
  const bundleReceiptPath = join(bundlePath, 'receipt.json')
  const exactGateReceipt = {
    schema: 2,
    builderMode: 'remote-native',
    builtOnHostMac: false,
    builtOnRemoteVm: true,
    builderHostOs: 'Linux',
    builderHostArchitecture: 'x86_64',
    containerImageId: `sha256:${'a'.repeat(64)}`,
    dockerfileSha256: sha256(join(root, 'Dockerfile.linux-vm-gate')),
    containerPayloadSha256: sha256(
      join(root, 'scripts', 'build-host-linux-vm-bundle-in-container.sh'),
    ),
    appGitSha: candidateCommit,
    appGitTree: candidateTree,
    appVersion: workspaceVersion,
    fipsGitSha,
    fipsGitTree,
    fipsVersion: fipsPackages['nvpn-fips-core'],
    rootCargoLockSha256: sha256(rootLock),
    rootRealizedCargoLockSha256,
    linuxCargoLockSha256: sha256(linuxLock),
    linuxRealizedCargoLockSha256,
    fipsPatchedLockPackages: fipsPackages,
    target: 'x86_64-unknown-linux-gnu',
    dockerPlatform: 'linux/amd64',
    containerBase: 'ubuntu:24.04',
    sourceDateEpoch,
    rustcVersion: 'rustc 1.95.0 (fixture 2026-01-01)',
    cargoVersion: 'cargo 1.95.0 (fixture 2026-01-01)',
  }
  const exactPackageReceipt = {
    schema: 2,
    artifactType: 'exact Debian package installed on Ubuntu VM',
    appGitSha: candidateCommit,
    appGitTree: candidateTree,
    fipsGitSha,
    fipsGitTree,
    appVersion: workspaceVersion,
    builderMode: exactGateReceipt.builderMode,
    builtOnHostMac: exactGateReceipt.builtOnHostMac,
    builtOnRemoteVm: exactGateReceipt.builtOnRemoteVm,
    builderHostOs: exactGateReceipt.builderHostOs,
    builderHostArchitecture: exactGateReceipt.builderHostArchitecture,
    containerImageId: exactGateReceipt.containerImageId,
    dockerfileSha256: exactGateReceipt.dockerfileSha256,
    containerPayloadSha256: exactGateReceipt.containerPayloadSha256,
  }
  const exactEnv = {
    ...process.env,
    NVPN_EXPECTED_FIPS_GIT_SHA: fipsGitSha,
    NVPN_EXPECTED_FIPS_GIT_TREE: fipsGitTree,
    NVPN_EXPECTED_FIPS_VERSION: fipsPackages['nvpn-fips-core'],
    NVPN_FIPS_REPO_PATH: fipsRoot,
    NVPN_HOST_LINUX_VM_BUILDER_MODE: 'remote-native',
    NVPN_HOST_LINUX_VM_NATIVE_BUILDER_HOST: 'fixture-builder',
    NVPN_HOST_LINUX_VM_RUST_TOOLCHAIN: '1.95.0',
  }
  const planFor = ({
    gateReceipt = exactGateReceipt,
    packageInstallReceipt = exactPackageReceipt,
    env = exactEnv,
    hostPlatform = 'darwin',
    hostArch = 'arm64',
    verificationCommit = candidateCommit,
    verificationTree = candidateTree,
  } = {}) => {
    writeFileSync(
      bundleReceiptPath,
      `${JSON.stringify(gateReceipt, null, 2)}\n`,
    )
    const receiptSha256 = sha256(bundleReceiptPath)
    return linuxPublicationVerificationPlan({
      env,
      tag: workspaceTag,
      candidateCommit: verificationCommit,
      candidateTree: verificationTree,
      gateReceipt,
      packageInstallReceipt: {
        ...packageInstallReceipt,
        bundleReceiptSha256: receiptSha256,
      },
      bundlePath,
      bundleReceiptPath,
      bundleReceiptSha256: receiptSha256,
      candidateRoot: root,
      hostPlatform,
      hostArch,
    })
  }

  const plan = planFor()
  assert.equal(
    plan.verifierPath,
    join(realpathSync(root), 'scripts', 'verify-host-linux-vm-bundle.py'),
  )
  assert.equal(plan.verifierArgs.length, 17 + fipsSpecs.length)
  assert.deepEqual(plan.verifierArgs.slice(0, 3), [
    realpathSync(bundlePath),
    realpathSync(bundleReceiptPath),
    candidateCommit,
  ])
  assert.equal(plan.verifierArgs[12], 'x86_64-unknown-linux-gnu')
  assert.equal(plan.verifierArgs[13], 'remote-native')
  assert.equal(plan.verifierArgs[14], '1.95.0')
  assert.deepEqual(plan.verifierArgs.slice(17), fipsSpecs)

  for (const mutation of [
    (packages) => { delete packages['nvpn-dtls'] },
    (packages) => { packages['nvpn-dtls'] = '0.17.2' },
    (packages) => { packages.unknown = packages['nvpn-dtls']; delete packages['nvpn-dtls'] },
  ]) {
    const packages = { ...fipsPackages }
    mutation(packages)
    assert.throws(
      () => planFor({ gateReceipt: { ...exactGateReceipt, fipsPatchedLockPackages: packages } }),
      /fipsPatchedLockPackages/,
    )
  }

  const dirtyPath = join(root, 'untracked-publication-input')
  writeFileSync(dirtyPath, 'dirty\n')
  assert.throws(() => planFor(), /worktree.*dirty/i)
  unlinkSync(dirtyPath)

  const dirtyFipsPath = join(fipsRoot, 'untracked-publication-input')
  writeFileSync(dirtyFipsPath, 'dirty\n')
  assert.doesNotThrow(() => planFor())
  unlinkSync(dirtyFipsPath)

  assert.doesNotThrow(() => planFor({
    env: {
      ...exactEnv,
      NVPN_FIPS_REPO_PATH: join(temporaryRoot, 'nonexistent-live-fips'),
    },
  }))

  for (const [field, value, message] of [
    ['NVPN_EXPECTED_FIPS_GIT_SHA', '', /exact lowercase NVPN_EXPECTED_FIPS_GIT_SHA/i],
    ['NVPN_EXPECTED_FIPS_GIT_TREE', '', /exact lowercase NVPN_EXPECTED_FIPS_GIT_TREE/i],
    ['NVPN_EXPECTED_FIPS_VERSION', '', /exact NVPN_EXPECTED_FIPS_VERSION/i],
    ['NVPN_EXPECTED_FIPS_VERSION', '0.4.53', /nvpn-fips-core 0\.4\.53/i],
  ]) {
    assert.throws(
      () => planFor({ env: { ...exactEnv, [field]: value } }),
      message,
      field,
    )
  }

  for (const [field, replacement, message] of [
    ['dockerfileSha256', 'b'.repeat(64), /dockerfileSha256/i],
    ['containerPayloadSha256', 'c'.repeat(64), /containerPayloadSha256/i],
    ['fipsGitSha', 'd'.repeat(40), /fipsGitSha/i],
    ['fipsGitTree', 'e'.repeat(40), /fipsGitTree/i],
    [
      'rootRealizedCargoLockSha256',
      'f'.repeat(64),
      /rootRealizedCargoLockSha256/i,
    ],
    ['linuxCargoLockSha256', '1'.repeat(64), /linuxCargoLockSha256/i],
    ['sourceDateEpoch', sourceDateEpoch + 1, /sourceDateEpoch/i],
    [
      'fipsPatchedLockPackages',
      { ...fipsPackages, 'nvpn-webrtc': '0.17.2' },
      /fipsPatchedLockPackages/i,
    ],
    ['rustcVersion', 'rustc 1.94.0 (forged 2026-01-01)', /Rust toolchain/i],
  ]) {
    const forgedGate = structuredClone(exactGateReceipt)
    const forgedPackage = structuredClone(exactPackageReceipt)
    forgedGate[field] = replacement
    if (field in forgedPackage) {
      forgedPackage[field] = replacement
    }
    assert.throws(
      () =>
        planFor({
          gateReceipt: forgedGate,
          packageInstallReceipt: forgedPackage,
        }),
      message,
    )
  }

  assert.throws(
    () =>
      planFor({
        env: {
          ...exactEnv,
          NVPN_HOST_LINUX_VM_BUILDER_MODE: '',
        },
      }),
    /explicit.*builder mode/i,
  )
  assert.throws(
    () =>
      planFor({
        env: {
          ...exactEnv,
          NVPN_HOST_LINUX_VM_NATIVE_BUILDER_HOST: '',
        },
      }),
    /explicit native builder host/i,
  )

  const localGate = {
    ...exactGateReceipt,
    builderMode: 'local-docker',
    builtOnHostMac: true,
    builtOnRemoteVm: false,
    builderHostOs: 'Darwin',
    builderHostArchitecture: 'x86_64',
  }
  assert.throws(
    () =>
      planFor({
        gateReceipt: localGate,
        packageInstallReceipt: {
          ...exactPackageReceipt,
          builderMode: localGate.builderMode,
          builtOnHostMac: localGate.builtOnHostMac,
          builtOnRemoteVm: localGate.builtOnRemoteVm,
          builderHostOs: localGate.builderHostOs,
          builderHostArchitecture: localGate.builderHostArchitecture,
        },
        env: {
          ...exactEnv,
          NVPN_HOST_LINUX_VM_BUILDER_MODE: 'local-docker',
          NVPN_HOST_LINUX_VM_NATIVE_BUILDER_HOST: '',
        },
      }),
    /arm64.*remote-native|remote-native.*arm64/i,
  )

  mkdirSync(join(root, 'docs'), { recursive: true })
  writeFileSync(join(root, 'docs', 'harness-only-note'), 'unchanged Linux inputs\n')
  capture('git', ['add', 'docs/harness-only-note'], root)
  capture(
    'git',
    [
      '-c',
      'user.name=Release Test',
      '-c',
      'user.email=release-test@example.invalid',
      'commit',
      '--quiet',
      '-m',
      'harness-only change',
    ],
    root,
  )
  const verificationCommit = capture('git', ['rev-parse', 'HEAD'], root)
  const verificationTree = capture('git', ['rev-parse', 'HEAD^{tree}'], root)
  assert.doesNotThrow(() => planFor({
    verificationCommit,
    verificationTree,
  }))
})

test('frozen FIPS publication identity comes from explicit proof and sealed Cargo.lock', (context) => {
  const sourceRoot = process.cwd()
  const root = mkdtempSync(join(tmpdir(), 'nvpn-frozen-fips-proof-'))
  context.after(() => rmSync(root, { recursive: true, force: true }))
  mkdirSync(join(root, 'scripts'), { recursive: true })
  copyFixtureInput(sourceRoot, 'Cargo.lock', join(root, 'Cargo.lock'))
  copyFixtureInput(
    sourceRoot,
    'scripts/verify-cargo-path-patch-lock.py',
    join(root, 'scripts', 'verify-cargo-path-patch-lock.py'),
  )
  const expected = {
    fipsGitSha: 'a'.repeat(40),
    fipsGitTree: 'b'.repeat(40),
    fipsVersion: fipsPackages['nvpn-fips-core'],
    fipsSpecifications: fipsSpecs,
    fipsPatchedLockPackages: fipsPackages,
    lockVerifierPath: join(
      realpathSync(root),
      'scripts',
      'verify-cargo-path-patch-lock.py',
    ),
  }
  assert.deepEqual(
    exactFipsPublicationCandidate({
      candidateRoot: root,
      env: {
        NVPN_EXPECTED_FIPS_GIT_SHA: expected.fipsGitSha,
        NVPN_EXPECTED_FIPS_GIT_TREE: expected.fipsGitTree,
        NVPN_EXPECTED_FIPS_VERSION: expected.fipsVersion,
        NVPN_FIPS_REPO_PATH: join(root, 'absent-and-irrelevant'),
      },
    }),
    expected,
  )
})

test('legacy 107 publication retains the eight-package receipt contract', (context) => {
  const root = mkdtempSync(join(tmpdir(), 'nvpn-legacy-fips-proof-'))
  context.after(() => rmSync(root, { recursive: true, force: true }))
  mkdirSync(join(root, 'scripts'))
  copyFixtureInput(process.cwd(), 'scripts/verify-cargo-path-patch-lock.py',
    join(root, 'scripts/verify-cargo-path-patch-lock.py'))
  const packages = {
    ...fipsPackages,
    'nvpn-fips-core': '0.4.107',
    'nvpn-fips-endpoint': '0.4.107',
    'nvpn-webrtc': '0.17.3',
  }
  delete packages['nvpn-dtls']
  writeFileSync(join(root, 'Cargo.lock'), 'version = 4\n\n' + Object.entries(packages)
    .map(([name, version]) => `[[package]]\nname = "${name}"\nversion = "${version}"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\nchecksum = "${'a'.repeat(64)}"\n`)
    .join('\n'))
  const candidate = exactFipsPublicationCandidate({ candidateRoot: root, env: {
    NVPN_EXPECTED_FIPS_GIT_SHA: 'a'.repeat(40),
    NVPN_EXPECTED_FIPS_GIT_TREE: 'b'.repeat(40),
    NVPN_EXPECTED_FIPS_VERSION: '0.4.107',
  } })
  assert.deepEqual(candidate.fipsPatchedLockPackages, packages)
  assert.equal(candidate.fipsSpecifications.length, 8)
})

test('Windows publication requires installer and artifact receipts to bind exact FIPS', () => {
  const expectedFips = {
    fipsGitSha: 'a'.repeat(40),
    fipsGitTree: 'b'.repeat(40),
    fipsVersion: '0.4.45',
  }
  const artifactReceipt = { ...expectedFips }
  const installerReceipt = { ...expectedFips }
  assert.deepEqual(
    validateWindowsPublicationFipsReceipts({
      artifactReceipt,
      installerReceipt,
      expectedFips,
    }),
    expectedFips,
  )

  for (const [receiptName, field, value] of [
    ['artifactReceipt', 'fipsGitSha', 'c'.repeat(40)],
    ['artifactReceipt', 'fipsGitTree', undefined],
    ['installerReceipt', 'fipsGitSha', undefined],
    ['installerReceipt', 'fipsGitTree', 'd'.repeat(40)],
    ['installerReceipt', 'fipsVersion', '0.4.44'],
  ]) {
    const candidate = {
      artifactReceipt: { ...artifactReceipt },
      installerReceipt: { ...installerReceipt },
      expectedFips,
    }
    if (value === undefined) {
      delete candidate[receiptName][field]
    } else {
      candidate[receiptName][field] = value
    }
    assert.throws(
      () => validateWindowsPublicationFipsReceipts(candidate),
      new RegExp(`${field}.*exact candidate`, 'i'),
    )
  }
})

function runtimeFixture() {
  const fixture = exactWindowsCratesIoFixture()
  return { ...fixture, runtimeVersion: '4.1.19\nfips_core_version: 0.4.53\n',
    cliSha256: fixture.artifactReceipt.payloads.cli.sha256,
    cliSize: fixture.artifactReceipt.payloads.cli.size }
}

test('registry runtime without Git metadata requires complete independent provenance', () => {
  const fixture = runtimeFixture()
  assert.equal(validateWindowsRuntimeFipsVersion(fixture).revisionFromRegistry, true)
  fixture.runtimeVersion = '4.1.19\nfips_core_version: 0.4.53 (rev cccccccccc)\n'
  assert.equal(validateWindowsRuntimeFipsVersion(fixture).revisionFromRegistry, false)
})

for (const [label, mutate] of [
  ['wrong version', f => { f.runtimeVersion = 'fips_core_version: 0.4.52' }],
  ['wrong revision', f => { f.runtimeVersion = 'fips_core_version: 0.4.53 (rev aaaaaaaaaa)' }],
  ['dirty revision', f => { f.runtimeVersion = 'fips_core_version: 0.4.53 (rev cccccccccc-dirty)' }],
  ['duplicate runtime rows', f => { f.runtimeVersion += 'fips_core_version: 0.4.53\n' }],
  ['missing source receipt', f => { f.sourceReceipt = {} }],
  ['wrong artifact hash', f => { f.cliSha256 = '0'.repeat(64) }],
  ['wrong artifact size', f => { f.cliSize++ }],
  ['wrong package checksum', f => { f.sourceReceipt.fipsCrates['nvpn-fips-core'].cargoLockChecksum = '0'.repeat(64) }],
  ['wrong package VCS', f => { f.sourceReceipt.fipsCrates['nvpn-fips-core'].packageVcsSha = '0'.repeat(40) }],
  ['unaccepted installer', f => { f.artifactReceipt.installerInstalledAndLaunched = false }],
]) {
  test(`registry runtime rejects ${label}`, () => {
    const fixture = runtimeFixture(); mutate(fixture)
    assert.throws(() => validateWindowsRuntimeFipsVersion(fixture))
  })
}

function macosRuntimeFixture() {
  const fixture = runtimeFixture()
  fixture.artifactReceipt = {
    receiptSchema: 1, artifactType: 'macOS company Developer ID Release gate package',
    configuration: 'Release', companySigningVerified: true,
    builtOnHost: true, builtOnTestVm: false,
    fipsGitSha: fixture.expectedFipsGitSha, fipsGitTree: fixture.expectedFipsGitTree,
    fipsCoreVersion: fixture.expectedFipsVersion, cliExecutableSha256: fixture.cliSha256,
  }
  return fixture
}

test('macOS registry runtime keeps exact signed payload and package provenance', () => {
  const fixture = macosRuntimeFixture()
  assert.equal(validateMacosRuntimeFipsVersion(fixture).revisionFromRegistry, true)
  fixture.runtimeVersion = `fips_core_version: ${fixture.expectedFipsVersion} (rev ${fixture.expectedFipsGitSha.slice(0, 10)})`
  assert.equal(validateMacosRuntimeFipsVersion(fixture).revisionFromRegistry, false)
})
for (const [label, mutate] of [
  ['wrong binary', f => { f.cliSha256 = '0'.repeat(64) }],
  ['wrong source', f => { f.artifactReceipt.fipsGitSha = '0'.repeat(40) }],
  ['wrong registry VCS', f => { f.exactPackages['nvpn-fips-core'].packageVcsSha = '0'.repeat(40) }],
  ['missing checksum', f => { delete f.exactPackages['nvpn-fips-endpoint'].cargoLockChecksum }],
  ['path replacement', f => { f.exactPackages['nvpn-fips-core'].source = null }],
  ['unsigned payload', f => { f.artifactReceipt.companySigningVerified = false }],
  ['wrong runtime version', f => { f.runtimeVersion = 'fips_core_version: 0.4.1' }],
  ['wrong runtime revision', f => { f.runtimeVersion = f.runtimeVersion.trimEnd() + ' (rev aaaaaaaaaa)' }],
  ['duplicate runtime rows', f => { f.runtimeVersion += f.runtimeVersion }],
]) {
  test(`macOS registry runtime rejects ${label}`, () => {
    const fixture = macosRuntimeFixture(); mutate(fixture)
    assert.throws(() => validateMacosRuntimeFipsVersion(fixture))
  })
}
